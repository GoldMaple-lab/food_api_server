require('dotenv').config(); // โหลด .env มาใช้งาน
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise'); // ใช้ mysql2/promise เพื่อรองรับ async/await
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const axios = require('axios'); // สำหรับเรียก API ภายนอก (เช่น สภาพอากาศ)
// --- 1. Express App & Port Setup ---
const app = express();
const port = process.env.PORT || 3000;

// --- 2. MySQL Connection Pool ---
// ใช้ Pool เพื่อการเชื่อมต่อที่มีประสิทธิภาพ
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// --- 3. Middlewares ---
app.use(cors()); // อนุญาตการเชื่อมต่อจากภายนอก
app.use(express.json()); // อ่าน JSON body
app.use(express.urlencoded({ extended: true })); // อ่าน Form data

// [!!] ทำให้โฟลเดอร์ 'public' เป็น static เพื่อเสิร์ฟไฟล์รูปภาพ
app.use(express.static('public'));

// --- 4. Multer (Image Upload) Setup ---
const storage = multer.diskStorage({
  destination: './public/uploads/',
  filename: (req, file, cb) => {
    // สร้างชื่อไฟล์ใหม่ที่ไม่ซ้ำ (fieldname-timestamp.ext)
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});

// Middleware ของ Multer
const upload = multer({
  storage: storage,
  limits: { fileSize: 5000000 }, // จำกัดขนาดไฟล์ 5MB
  fileFilter: (req, file, cb) => {
    // [!!] ---- โค้ดใหม่ที่ยืดหยุ่นกว่า ----
    // เราจะเช็คที่ mimetype (ประเภทไฟล์จริงๆ)
    if (file.mimetype == "image/jpeg" || 
        file.mimetype == "image/png" || 
        file.mimetype == "image/gif" ||
        file.mimetype == "image/webp" ||  // [!] อนุญาต .webp
        file.mimetype == "image/heic") {  // [!] อนุญาต .heic (iPhone)

      cb(null, true); // (อนุญาตไฟล์นี้)

    } else {
      // ถ้าไฟล์ไม่ตรงกับที่อนุญาต
      console.log("Rejected file mimetype:", file.mimetype); // [!] Log บอกเรา
      cb(new Error('Images Only! (Unsupported file type)')); // [!] ส่ง Error ที่ชัดเจนขึ้น
    }
  }
});

// --- 5. Auth Middleware (checkAuth) ---
// Middleware สำหรับตรวจสอบ Token ในทุก Request ที่ต้องป้องกัน
const checkAuth = (req, res, next) => {
  try {
    // ดึง Token จาก Header "Authorization: Bearer <token>"
    const token = req.headers.authorization.split(' ')[1];
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    
    // ส่งข้อมูล user ที่ถอดรหัสแล้ว (userId, role) ไปกับ Request
    req.userData = decodedToken;
    next(); // ไปยัง route ถัดไป
  } catch (error) {
    return res.status(401).json({ message: 'Authentication failed' });
  }
};

// --- 6. API Routes ---

// Route ทดสอบ
app.get('/', (req, res) => {
  res.send('Smart Food API Server is running!');
});

// === Auth Routes ===

// 1. Register (สมัครสมาชิก)
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name, role } = req.body;
    if (!email || !password || !role) {
      return res.status(400).json({ message: 'Email, password, and role are required.' });
    }
    
    // เข้ารหัสรหัสผ่าน
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const [result] = await pool.execute(
      'INSERT INTO users (email, password_hash, name, role) VALUES (?, ?, ?, ?)',
      [email, hashedPassword, name, role]
    );
    
    res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
  } catch (error) {
    console.error("Register Error:", error);
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'Email already exists.' });
    }
    res.status(500).json({ message: 'Error registering user' });
  }
});

// 2. Login (เข้าสู่ระบบ)
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    const user = rows[0];

    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // ตรวจสอบรหัสผ่าน
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (isMatch) {
      // สร้าง Token
      const token = jwt.sign(
        { userId: user.user_id, role: user.role, name: user.name },
        process.env.JWT_SECRET,
        { expiresIn: '24h' } // Token มีอายุ 24 ชั่วโมง
      );
      res.json({ token, userId: user.user_id, name: user.name, role: user.role });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// === Image Upload Route ===

// 3. Upload Image (อัปโหลดรูป)
// [!!] ใช้ checkAuth เพื่อให้แน่ใจว่าต้องล็อคอินก่อนอัปโหลด
app.post('/api/upload-image', checkAuth, upload.single('image'), (req, res) => {
  // 'image' คือ key ที่ Postman/Flutter ต้องใช้
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded.' });
  }
  
  // [!!] สร้าง URL จาก IP ใน .env
  const serverIp = process.env.SERVER_IP;
  const imageUrl = `http://${serverIp}:${port}/uploads/${req.file.filename}`;
  
  // ส่ง URL กลับไปให้แอป
  res.json({ imageUrl: imageUrl });
});

// === Store Routes (Seller) ===

// 4. Create Store (สร้างร้าน)
// [!!] ใช้ checkAuth
app.post('/api/stores', checkAuth, async (req, res) => {
  // ตรวจสอบว่าเป็น Seller หรือไม่
  if (req.userData.role !== 'seller') {
    return res.status(403).json({ message: 'Access denied. Only sellers can create stores.' });
  }
  
  try {
    const { storeName, description, storeImageUrl } = req.body;
    const sellerId = req.userData.userId; // ดึง ID ผู้ขายจาก Token
    
    // [!!] ตรวจสอบว่ามีชื่อร้านหรือไม่
    if (!storeName) {
      return res.status(400).json({ message: 'Store name is required.' });
    }

    const [result] = await pool.execute(
      'INSERT INTO stores (seller_id, store_name, description, store_image_url) VALUES (?, ?, ?, ?)',
      [
        sellerId, 
        storeName, 
        description || null, 
        storeImageUrl || null 
      ]
    );
    res.status(201).json({ message: 'Store created', storeId: result.insertId });
  } catch (error) {
    console.error("Create Store Error:", error);
    res.status(500).json({ message: 'Error creating store', error: error.message }); // ส่ง error message กลับไปด้วย
  }
});

// 5. Add Menu Item (อัปเกรด)
app.post('/api/stores/:storeId/menus', checkAuth, async (req, res) => {
  const { storeId } = req.params;
  const sellerId = req.userData.userId;
  
  // [!!] รับข้อมูลใหม่
  const { title, description, price, calories, imageUrl, recipe, tag_ids, mood_ids } = req.body;

  if (!title || !price) {
    return res.status(400).json({ message: 'Title and Price are required.' });
  }

  // [!!] ใช้ Transaction
  let connection;
  try {
    connection = await pool.getConnection(); // 1. ขอ Connection
    await connection.beginTransaction(); // 2. เริ่ม Transaction

    // 3. ตรวจสอบความเป็นเจ้าของร้าน
    const [storeRows] = await connection.execute('SELECT * FROM stores WHERE store_id = ? AND seller_id = ?', [storeId, sellerId]);
    if (storeRows.length === 0) {
      throw new Error('Access denied. You do not own this store.');
    }

    // 4. เพิ่มเมนูหลัก (พร้อม recipe)
    const [result] = await connection.execute(
      'INSERT INTO menu_items (store_id, title, description, price, calories, image_url, recipe) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [
        storeId, 
        title, 
        description || null,
        price, 
        calories || 0,
        imageUrl || null,
        recipe ? JSON.stringify(recipe) : null // [!] แปลง JSON เป็น String (ถ้า DB type เป็น TEXT)
        // (ถ้า DB type เป็น JSON ให้ส่ง recipe || null)
      ]
    );
    const newMenuId = result.insertId;

    // 5. เพิ่ม Tags (ถ้ามี)
    if (tag_ids && tag_ids.length > 0) {
      const tagValues = tag_ids.map(tagId => [newMenuId, tagId]);
      await connection.query('INSERT INTO menu_item_tags (menu_id, tag_id) VALUES ?', [tagValues]);
    }

    // 6. เพิ่ม Moods (ถ้ามี)
    if (mood_ids && mood_ids.length > 0) {
      const moodValues = mood_ids.map(moodId => [newMenuId, moodId]);
      await connection.query('INSERT INTO menu_item_moods (menu_id, mood_id) VALUES ?', [moodValues]);
    }
    
    // 7. สำเร็จ
    await connection.commit();
    res.status(201).json({ message: 'Menu item added successfully', menuId: newMenuId });

  } catch (error) {
    // 8. ถ้าพลาด
    if (connection) await connection.rollback();
    console.error("Add Menu Error:", error);
    res.status(500).json({ message: error.message || 'Error adding menu item' });
  } finally {
    // 9. คืน Connection
    if (connection) connection.release();
  }
});

// === Read Routes (Buyer) ===
// (เพิ่ม API สำหรับแอปผู้ซื้อใน Phase 3)

// 6. Get All Stores (ดึงร้านค้าทั้งหมด)
app.get('/api/stores', async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT store_id, store_name, description, store_image_url FROM stores');
    res.json(rows);
  } catch (error) {
    console.error("Get Stores Error:", error);
    res.status(500).json({ message: 'Error fetching stores' });
  }
});

// 7. Get Menus for a Store (อัปเกรด)
app.get('/api/stores/:storeId/menus', async (req, res) => {
  try {
    const { storeId } = req.params;
    
    // [!!] ---- จุดแก้ไข: เพิ่ม LEFT JOINs และ GROUP_CONCAT ----
    const query = `
      SELECT 
        m.*, 
        s.store_name,
        GROUP_CONCAT(DISTINCT t.tag_name) AS tags,
        GROUP_CONCAT(DISTINCT mo.mood_name) AS moods
      FROM menu_items m
      LEFT JOIN stores s ON m.store_id = s.store_id
      LEFT JOIN menu_item_tags mit ON m.menu_id = mit.menu_id
      LEFT JOIN tags t ON mit.tag_id = t.tag_id
      LEFT JOIN menu_item_moods mim ON m.menu_id = mim.menu_id
      LEFT JOIN moods mo ON mim.mood_id = mo.mood_id
      WHERE m.store_id = ?
      GROUP BY m.menu_id
    `;
    // [!!] --------------------------------------------------

    const [rows] = await pool.execute(query, [storeId]);
    res.json(rows);
  } catch (error) {
    console.error("Get Menus Error:", error);
    res.status(500).json({ message: 'Error fetching menus' });
  }
});

// 8. Get My Store (สำหรับ Seller ที่ล็อคอินแล้ว)
// [!!] ใช้ checkAuth
app.get('/api/my-store', checkAuth, async (req, res) => {
  // เช็ค Role
  if (req.userData.role !== 'seller') {
    return res.status(403).json({ message: 'Access denied. Sellers only.' });
  }

  try {
    const sellerId = req.userData.userId;
    const [rows] = await pool.execute(
      'SELECT * FROM stores WHERE seller_id = ?', 
      [sellerId]
    );

    if (rows.length > 0) {
      // 200 OK - คืนค่าข้อมูลร้านค้า
      res.json(rows[0]);
    } else {
      // 200 OK - คืนค่า null (ไม่ใช่ Error) เพื่อบอกแอปว่า "ยังไม่มีร้าน"
      res.status(200).json(null);
    }
  } catch (error) {
    console.error("Get My Store Error:", error);
    res.status(500).json({ message: 'Error fetching store data' });
  }
});

// 9. Update Menu Item (อัปเกรด)
app.put('/api/menus/:menuId', checkAuth, async (req, res) => {
  const { menuId } = req.params;
  const sellerId = req.userData.userId;
  
  // [!!] รับข้อมูลใหม่
  const { title, description, price, calories, imageUrl, recipe, tag_ids, mood_ids } = req.body;
  
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    // 1. ตรวจสอบความเป็นเจ้าของ
    const [menuRows] = await connection.execute(
      'SELECT * FROM menu_items m JOIN stores s ON m.store_id = s.store_id WHERE m.menu_id = ? AND s.seller_id = ?',
      [menuId, sellerId]
    );
    if (menuRows.length === 0) {
      throw new Error('Access denied. You do not own this menu item.');
    }
    
    // 2. อัปเดตเมนูหลัก (พร้อม recipe)
    await connection.execute(
      `UPDATE menu_items SET 
        title = ?, description = ?, price = ?, calories = ?, image_url = ?, recipe = ?
      WHERE menu_id = ?`,
      [
        title || menuRows[0].title,
        description || menuRows[0].description,
        price || menuRows[0].price,
        calories || menuRows[0].calories,
        imageUrl || menuRows[0].image_url,
        recipe ? JSON.stringify(recipe) : menuRows[0].recipe, // [!] อัปเดต recipe
        menuId
      ]
    );

    // 3. อัปเดต Tags (ลบของเก่าทั้งหมด, แล้วเพิ่มของใหม่)
    await connection.execute('DELETE FROM menu_item_tags WHERE menu_id = ?', [menuId]);
    if (tag_ids && tag_ids.length > 0) {
      const tagValues = tag_ids.map(tagId => [menuId, tagId]);
      await connection.query('INSERT INTO menu_item_tags (menu_id, tag_id) VALUES ?', [tagValues]);
    }

    // 4. อัปเดต Moods (ลบของเก่าทั้งหมด, แล้วเพิ่มของใหม่)
    await connection.execute('DELETE FROM menu_item_moods WHERE menu_id = ?', [menuId]);
    if (mood_ids && mood_ids.length > 0) {
      const moodValues = mood_ids.map(moodId => [menuId, moodId]);
      await connection.query('INSERT INTO menu_item_moods (menu_id, mood_id) VALUES ?', [moodValues]);
    }

    // 5. สำเร็จ
    await connection.commit();
    res.json({ message: 'Menu item updated successfully' });

  } catch (error) {
    if (connection) await connection.rollback();
    console.error("Update Menu Error:", error);
    res.status(500).json({ message: error.message || 'Error updating menu item' });
  } finally {
    if (connection) connection.release();
  }
});

// 10. Delete Menu Item (ลบเมนู)
// [!!] ใช้ checkAuth
app.delete('/api/menus/:menuId', checkAuth, async (req, res) => {
  try {
    const { menuId } = req.params;
    const sellerId = req.userData.userId;

    // [!!] Security: ตรวจสอบความเป็นเจ้าของก่อนลบ
    const [menuRows] = await pool.execute(
      'SELECT * FROM menu_items m JOIN stores s ON m.store_id = s.store_id WHERE m.menu_id = ? AND s.seller_id = ?',
      [menuId, sellerId]
    );

    if (menuRows.length === 0) {
      return res.status(403).json({ message: 'Access denied.' });
    }

    // [!!] TODO: ก่อนลบเมนู, ควรลบ Tag ที่เชื่อมกันใน 'menu_item_tags' ก่อน
    // (สำหรับตอนนี้ เราลบแค่เมนูหลัก)

    await pool.execute('DELETE FROM menu_items WHERE menu_id = ?', [menuId]);

    res.json({ message: 'Menu item deleted' });
  } catch (error) {
    console.error("Delete Menu Error:", error);
    res.status(500).json({ message: 'Error deleting menu item' });
  }
});

// 11. Create Order (สร้างออเดอร์ - ผู้ซื้อ)
// [!!] ใช้ checkAuth
app.post('/api/orders', checkAuth, async (req, res) => {
  const buyerId = req.userData.userId;
  const { store_id, total_price, items } = req.body; // items คือ [ {menu_id, quantity, price}, ... ]

  if (req.userData.role !== 'buyer') {
    return res.status(403).json({ message: 'Only buyers can create orders.' });
  }

  // 1. สร้าง Order หลัก
  try {
    const [orderResult] = await pool.execute(
      'INSERT INTO orders (buyer_id, store_id, total_price) VALUES (?, ?, ?)',
      [buyerId, store_id, total_price]
    );
    const orderId = orderResult.insertId;

    // 2. เพิ่ม Order Items (วน Loop)
    const itemPromises = items.map(item => {
      return pool.execute(
        'INSERT INTO order_items (order_id, menu_id, quantity, price_at_time) VALUES (?, ?, ?, ?)',
        [orderId, item.menu_id, item.quantity, item.price_at_time]
      );
    });
    await Promise.all(itemPromises); // รันพร้อมกัน

    // 3. [!!] Real-time: แจ้งเตือนผู้ขาย
    const io = req.app.get('io'); // ดึง io ที่เราเซ็ตไว้
    const [storeRows] = await pool.execute('SELECT seller_id FROM stores WHERE store_id = ?', [store_id]);
    const sellerId = storeRows[0].seller_id;
    
    // [!] ส่งไปที่ "ห้อง" ของผู้ขายคนนั้น
    io.to(sellerId.toString()).emit('new_order', { orderId: orderId, message: 'You have a new order!' });

    res.status(201).json({ message: 'Order created successfully', orderId: orderId });
  } catch (error) {
    console.error("Create Order Error:", error);
    res.status(500).json({ message: 'Error creating order' });
  }
});

// 12. Get My Store Orders (ดูออเดอร์ของร้าน - ผู้ขาย)
app.get('/api/my-store/orders', checkAuth, async (req, res) => {
  if (req.userData.role !== 'seller') {
    return res.status(403).json({ message: 'Sellers only.' });
  }
  const sellerId = req.userData.userId;
  
  // (SQL นี้จะดึงออเดอร์ทั้งหมดที่อยู่ในร้านของผู้ขายคนนี้)
  const [orders] = await pool.execute(
    'SELECT o.* FROM orders o JOIN stores s ON o.store_id = s.store_id WHERE s.seller_id = ? ORDER BY o.created_at DESC',
    [sellerId]
  );
  res.json(orders);
});

// 13. Update Order Status (อัปเดตสถานะ - ผู้ขาย)
app.patch('/api/orders/:orderId/status', checkAuth, async (req, res) => {
  if (req.userData.role !== 'seller') {
    return res.status(403).json({ message: 'Sellers only.' });
  }
  
  const { orderId } = req.params;
  const { status } = req.body; // เช่น "accepted" หรือ "completed"
  const sellerId = req.userData.userId;
  
  try {
    // [!] ตรวจสอบว่าผู้ขายเป็นเจ้าของออเดอร์นี้จริง
    const [orderRows] = await pool.execute(
      'SELECT o.* FROM orders o JOIN stores s ON o.store_id = s.store_id WHERE o.order_id = ? AND s.seller_id = ?',
      [orderId, sellerId]
    );

    if (orderRows.length === 0) {
      return res.status(404).json({ message: 'Order not found or access denied.' });
    }

    // 1. อัปเดต DB
    await pool.execute('UPDATE orders SET status = ? WHERE order_id = ?', [status, orderId]);

    // 2. [!!] Real-time: แจ้งเตือนผู้ซื้อ
    const io = req.app.get('io');
    const buyerId = orderRows[0].buyer_id;
    // [!] ส่งไปที่ "ห้อง" ของผู้ซื้อคนนั้น
    io.to(buyerId.toString()).emit('order_update', { orderId: orderId, status: status });

    res.json({ message: 'Order status updated' });
  } catch (error) {
    console.error("Update Status Error:", error);
    res.status(500).json({ message: 'Error updating status' });
  }
});

// 14. Get My Orders (ดูประวัติออเดอร์ - ผู้ซื้อ)
app.get('/api/my-orders', checkAuth, async (req, res) => {
  if (req.userData.role !== 'buyer') {
    return res.status(403).json({ message: 'Buyers only.' });
  }
  const buyerId = req.userData.userId;
  const [orders] = await pool.execute(
    'SELECT * FROM orders WHERE buyer_id = ? ORDER BY created_at DESC',
    [buyerId]
  );
  res.json(orders);
});

// 15. Get All Tags
app.get('/api/tags', async (req, res) => {
  try {
    const [tags] = await pool.execute('SELECT * FROM tags ORDER BY tag_name');
    res.json(tags);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching tags' });
  }
});

// 16. Get All Moods
app.get('/api/moods', async (req, res) => {
  try {
    const [moods] = await pool.execute('SELECT * FROM moods ORDER BY mood_name');
    res.json(moods);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching moods' });
  }
});

// === Smart Advisor Endpoints ===

// 17. Weather API (ของจริง - ดึงข้อมูลจาก OpenWeatherMap)
app.get('/api/weather', async (req, res) => {

  // [!!] เป้าหมาย: อ.เมือง จ.ตรัง
  const city = 'Trang'; 
  const country = 'TH';
  const apiKey = process.env.OWM_API_KEY; // ดึง Key ลับจาก .env

  // เช็คว่ามี Key หรือไม่
  if (!apiKey) {
    console.error("Weather API Key is missing from .env");
    return res.status(500).json({ message: 'Weather service is not configured.' });
  }

  const url = `https://api.openweathermap.org/data/2.5/weather?q=${city},${country}&appid=${apiKey}&units=metric&lang=th`;

  try {
    const response = await axios.get(url);

    // [!] เราจะย่อยข้อมูลเฉพาะที่จำเป็นส่งให้แอป
    const data = response.data;
    const condition = data.weather[0].main.toLowerCase(); // 'clear', 'rain', 'clouds'

    res.json({ 
      condition: condition,           // สภาพอากาศหลัก (เช่น 'rain')
      description: data.weather[0].description, // (เช่น 'ฝนตกปรอยๆ')
      temp: data.main.temp,           // อุณหภูมิ (เซลเซียส)
      city: data.name                 // (จะคืนค่า "Trang")
    });

  } catch (error) {
    console.error("Weather API Error:", error.response?.data || error.message);
    res.status(500).json({ message: 'Error fetching weather' });
  }
});

// 18. Add Food Log (บันทึกการกิน)
app.post('/api/food-log', checkAuth, async (req, res) => {
  if (req.userData.role !== 'buyer') {
    return res.status(403).json({ message: 'Buyers only.' });
  }
  const userId = req.userData.userId;
  const { menu_id, title, meal_time, calories, eaten_at } = req.body;

  try {
    await pool.execute(
      'INSERT INTO food_logs (user_id, menu_id, title, meal_time, calories, eaten_at) VALUES (?, ?, ?, ?, ?, ?)',
      [userId, menu_id || null, title, meal_time, calories, eaten_at || new Date()]
    );
    res.status(201).json({ message: 'Food logged successfully' });
  } catch (error) {
    console.error("Food Log Error:", error);
    res.status(500).json({ message: 'Error logging food' });
  }
});

// 19. Get Food Log (ดึงประวัติการกิน)
// (เราจะใช้สำหรับหน้า Calendar และ Insights)
app.get('/api/food-log', checkAuth, async (req, res) => {
  const userId = req.userData.userId;
  // (ดึงตามช่วงวันที่ ?start=...&end=...)
  const { start, end } = req.query; 

  try {
    // (Query นี้จะดึงทั้งหมดก่อน เพื่อความง่าย)
    const [logs] = await pool.execute(
      'SELECT * FROM food_logs WHERE user_id = ? ORDER BY eaten_at DESC',
      [userId]
    );
    res.json(logs);
  } catch (error) {
    console.error("Get Log Error:", error);
    res.status(500).json({ message: 'Error fetching logs' });
  }
});

// 20. [!!] "Smart Search" (อัปเกรด)
app.get('/api/menus/search', async (req, res) => {
  const { tags, moods, type } = req.query;
  
  let query = `
    SELECT 
      m.*, 
      s.store_name,
      GROUP_CONCAT(DISTINCT t.tag_name) AS tags,
      GROUP_CONCAT(DISTINCT mo.mood_name) AS moods
    FROM menu_items m
    LEFT JOIN stores s ON m.store_id = s.store_id
    LEFT JOIN menu_item_tags mit ON m.menu_id = mit.menu_id
    LEFT JOIN tags t ON mit.tag_id = t.tag_id
    LEFT JOIN menu_item_moods mim ON m.menu_id = mim.menu_id
    LEFT JOIN moods mo ON mim.mood_id = mo.mood_id
  `;
  
  const whereClauses = [];
  const params = [];

  // ... (Filter by Type, Tags, Moods - เหมือนเดิม) ...
  if (type === 'order') {
    whereClauses.push('m.store_id IS NOT NULL');
  } else if (type === 'recipe') {
    whereClauses.push('m.store_id IS NULL');
  }
  if (tags) {
    const tagIds = tags.split(',').map(id => parseInt(id)); 
    whereClauses.push(`mit.tag_id IN (?)`);
    params.push(tagIds);
  }
  if (moods) {
    const moodIds = moods.split(',').map(id => parseInt(id)); 
    whereClauses.push(`mim.mood_id IN (?)`);
    params.push(moodIds);
  }

  if (whereClauses.length > 0) {
    query += ' WHERE ' + whereClauses.join(' AND ');
  }
  
  // [!!] ---- จุดแก้ไข: เพิ่ม GROUP BY ----
  query += ' GROUP BY m.menu_id';
  // [!!] ----------------------------------
  
  query += ' ORDER BY m.title LIMIT 50';

  try {
  const [menus] = await pool.query(query, params); // [!!] เปลี่ยน execute เป็น query
  res.json(menus);
} catch (error) {
    console.error("Search Error:", error);
    res.status(500).json({ message: 'Error searching menus', error: error.message });
  }
});
app.put('/api/my-store', checkAuth, async (req, res) => {
  // 1. ตรวจสอบว่าเป็น Seller
  if (req.userData.role !== 'seller') {
    return res.status(403).json({ message: 'Sellers only.' });
  }

  const sellerId = req.userData.userId;
  const { storeName, description, storeImageUrl } = req.body;

  try {
    // 2. ดึงข้อมูลร้านเดิม (เผื่อผู้ใช้ไม่อัปเดตบางช่อง)
    const [storeRows] = await pool.execute('SELECT * FROM stores WHERE seller_id = ?', [sellerId]);
    if (storeRows.length === 0) {
      return res.status(404).json({ message: 'Store not found.' });
    }
    const oldStore = storeRows[0];

    // 3. อัปเดตข้อมูล
    const [result] = await pool.execute(
      `UPDATE stores SET 
        store_name = ?, 
        description = ?, 
        store_image_url = ? 
      WHERE seller_id = ?`,
      [
        storeName || oldStore.store_name, // ถ้าไม่ส่งมา, ใช้ค่าเดิม
        description || oldStore.description,
        storeImageUrl || oldStore.store_image_url,
        sellerId
      ]
    );

    res.json({ message: 'Store updated successfully' });

  } catch (error) {
    console.error("Update Store Error:", error);
    res.status(500).json({ message: 'Error updating store' });
  }
});
// (ใน index.js)

// ... (โค้ด API อื่นๆ ทั้งหมดอยู่ด้านบน) ...

// --- 7. Start Server & Socket.io ---
const http = require('http');
const { Server } = require("socket.io");

const server = http.createServer(app); // [!] สร้าง Server ด้วย http ก่อน
const io = new Server(server, { // [!] เอา socket.io มาครอบ
  cors: {
    origin: "*", // [!] อนุญาตทุก Cilent
    methods: ["GET", "POST"]
  }
});

// [!!] ทำให้ IO ใช้ได้ในทุก Request (สำคัญมาก)
app.set('io', io); // เก็บ io ไว้ใน app settings

// [!] Logic การเชื่อมต่อ Socket
io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  // [!] สร้าง "ห้อง" ส่วนตัวสำหรับ User
  socket.on('join_room', (userId) => {
    console.log(`User ${userId} joined room ${userId}`);
    socket.join(userId); // ให้ User นี้เข้าห้องชื่อเดียวกับ ID ตัวเอง
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// [!] เปลี่ยนจาก app.listen เป็น server.listen
server.listen(port, () => {
  console.log(`Server is listening on http://localhost:${port}`);
  console.log(`(API is accessible on your network at http://${process.env.SERVER_IP}:${port})`);
});