const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

const secretKey = 'yourSecretKey'; // Change to a secure key

// MySQL Database Connection
const db = mysql.createConnection({
    host: 'sql12.freemysqlhosting.net',  // or your host address
    user: 'sql12730750',       // your MySQL username
    password: 'JMku55sTDE',       // your MySQL password
    database: 'sql12730750' // your database name
});


db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err);
    } else {
        console.log('Database connected.');
    }
});

app.get('/getall',(req, res) => {
    const sql = 'SELECT * FROM user';
    db.query(sql, [req.user], (err, results) => {
        if (err) return res.status(500).send(err);
        res.status(200).json(results);
    });
})

app.get('/getorders',(req, res) => {
    const sql = 'SELECT * FROM orders';
    db.query(sql, [req.user], (err, results) => {
        if (err) return res.status(500).send(err);
        res.status(200).json(results);
    });
})

app.post('/user', (req, res) => {
    const { uid } = req.body;
  
    if (!uid) {
      return res.status(400).json({ error: 'UID is required' });
    }
  
    const sql = 'SELECT * FROM user WHERE uid = ?';
    db.query(sql, [uid], (err, results) => {
      if (err) {
        console.error('Database query error:', err);
        return res.status(500).send({ error: 'Database query error' });
      }
  
      if (results.length > 0) {
        res.status(200).json(results[0]); // ส่งข้อมูลผู้ใช้กลับ
      } else {
        res.status(404).json({ message: 'User not found' });
      }
    });
  });

// Register User
app.post('/register', (req, res) => {
    const { user_name, user_email, user_pass, user_type = 0} = req.body;
    user_wallet=500
    // Hash the password
    bcrypt.hash(user_pass, 10, (err, hash) => {
        if (err) throw err;

        const sql = 'INSERT INTO user (user_name, user_email, user_pass, user_type ,user_wallet) VALUES (?, ?, ?, ?,?)';
        db.query(sql, [user_name, user_email, hash, user_type,user_wallet], (err, result) => {
            if (err) return res.status(500).send(err);
            res.status(201).json({ message: 'User registered successfully!' });
        });
    });
});

// Login User
// Login User
app.post('/login', (req, res) => {
    const { user_email, user_pass } = req.body;

    const sql = 'SELECT * FROM user WHERE user_email = ?';
    db.query(sql, [user_email], (err, results) => {
        if (err) return res.status(500).send(err);
        if (results.length === 0) return res.status(404).json({ message: 'User not found' });

        const user = results[0];

        bcrypt.compare(user_pass, user.user_pass, (err, isMatch) => {
            if (err) throw err;
            if (!isMatch) return res.status(401).json({ message: 'Invalid password' });

            // ส่งค่า user_type กลับไปยัง frontend ด้วย
            const token = jwt.sign({ uid: user.uid }, secretKey, { expiresIn: '1h' });
            res.status(200).json({ 
                message: 'Login successful!',
                token,
                results: [{ user_type: user.user_type, ...user }]
            });
        });
    });
});
app.get('/allLotto', (req, res) => {
  const sql = 'SELECT l.l_number, o.o_status, l.wid FROM lotto l LEFT JOIN orders o ON l.lid = o.lid ORDER BY l.l_number ASC'; // เพิ่ม wid เพื่อแสดงเลขที่ถูกรางวัล

  db.query(sql, (err, results) => {
      if (err) {
          console.error('Database query error:', err);
          return res.status(500).json({ message: 'Database error', error: err });
      }
      res.status(200).json(results); // ส่งข้อมูลผลลัพธ์ทั้งหมดกลับในรูปแบบ JSON
  });
});
app.get('/getallLotto', (req, res) => {
    const query = 'SELECT * FROM lotto  ORDER BY l_number ASC';

    db.query(query, (err, results) => {
      if (err) {
        res.status(500).send({ error: 'Error fetching lotto numbers' });
      } else {
        res.status(200).json(results); // ส่งข้อมูลทั้งหมดในรูปแบบ JSON
      }
    });
  });

  app.get('/getLottoWin', (req, res) => {
    const query = `
      SELECT l.*, COALESCE(w.reward, 0) AS reward
      FROM lotto l
      LEFT JOIN winner w ON l.wid = w.wid
      WHERE l.wid != 0
      ORDER BY l.wid ASC;
    `;
  
    db.query(query, (err, results) => {
      if (err) {
        console.error('Error fetching lotto numbers:', err);
        return res.status(500).send({ error: 'Error fetching lotto numbers' });
      }
  
      res.status(200).json(results);
    });
  });
  
  

  app.post('/getLotto', (req, res) => {
    const { uid } = req.body;  // ดึง uid จาก body สำหรับคำขอ POST
    const query = 'SELECT * FROM orders WHERE uid=?';
  
    db.query(query, [uid], (err, results) => {
      if (err) {
        res.status(500).send({ error: 'Error fetching lotto numbers' });
      } else {
        res.status(200).json(results); // ส่งข้อมูลทั้งหมดในรูปแบบ JSON
      }
    });
  });

  app.post('/buy', (req, res) => {
    const { uid, lid, OStatus = 0 } = req.body;

    // ตรวจสอบข้อมูลที่ส่งเข้ามาว่าครบถ้วนหรือไม่
    if (uid === undefined || lid === undefined) {
        console.error('Missing uid or lid in request body:', req.body);
        return res.status(400).json({ message: 'Incomplete data' });
    }

    // สร้าง SQL สำหรับการ Insert
    const sql = 'INSERT INTO orders (uid, lid, O_Status) VALUES (?, ?, ?)';

    // ทำการ Insert ลงฐานข้อมูล
    db.query(sql, [uid, lid, OStatus], (err, result) => {
        if (err) {
            console.error('Database insert error:', err);
            return res.status(500).json({ message: 'Database error', error: err });
        }
        // หากสำเร็จให้ตอบกลับไป
        res.status(201).json({ message: 'Lotto purchased successfully!', oid: result.insertId });
    });
});

app.put('/updateLotto', (req, res) => {
  const { lid, wid } = req.body;

  console.log("Received data for update:", req.body); // Print received data

  if (!lid || !wid) {
    return res.status(400).json({ message: 'Incomplete data' });
  }

  // Validate wid

  const sql = 'UPDATE lotto SET wid = ? WHERE lid = ?';
  db.query(sql, [wid, lid], (err, result) => {
    if (err) {
      console.error('Database update error:', err);
      return res.status(500).send(err);
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Lotto not found' });
    }

    res.status(200).json({ message: Lotto number updated successfully for id ${lid} });
  });
});

app.put('/updateUser', (req, res) => {
  const { uid, userName, userEmail } = req.body;

  // Validate input
  if (!uid || !userName || !userEmail) {
    return res.status(400).send({ status: 'error', message: 'Missing required fields' });
  }

  // SQL query to update user information
  const query = 'UPDATE user SET user_name = ?, user_email = ? WHERE uid = ?';
  
  db.query(query, [userName, userEmail, uid], (err, results) => {
    if (err) {
      return res.status(500).send({ status: 'error', message: 'Error updating user information' });
    }
    
    // Check if any rows were affected
    if (results.affectedRows > 0) {
      res.status(200).send({ status: 'success', message: 'User information updated successfully' });
    } else {
      res.status(404).send({ status: 'error', message: 'User not found' });
    }
  });
});

app.post('/claimPrize', (req, res) => {
  const { uid, wid } = req.body; // รับ uid และ wid จาก request body

  if (!uid || !wid) {
    return res.status(400).json({ error: 'Missing uid or wid' });
  }

  // ขั้นตอนที่ 1: ดึงข้อมูล lid ที่เกี่ยวข้องกับ wid
  const getLidQuery = 'SELECT lid FROM lotto WHERE wid = ?';
  db.query(getLidQuery, [wid], (err, results) => {
    if (err) {
      console.error('Failed to retrieve lid from lotto:', err.message);
      return res.status(500).json({ error: 'Failed to retrieve lid from lotto' });
    }

    if (results.length > 0) {
      const lid = results[0].lid;

      // ขั้นตอนที่ 2: ดึงข้อมูล reward สำหรับ wid
      const rewardQuery = 'SELECT reward FROM winner WHERE wid = ?';
      db.query(rewardQuery, [wid], (err, results) => {
        if (err) {
          console.error('Failed to retrieve reward amount:', err.message);
          return res.status(500).json({ error: 'Failed to retrieve reward amount' });
        }

        if (results.length > 0) {
          const rewardAmount = results[0].reward;

          // ขั้นตอนที่ 3: ตรวจสอบสถานะคำสั่งซื้อปัจจุบัน
          const orderStatusQuery = 'SELECT o_status FROM orders WHERE uid = ? AND lid = ?';
          db.query(orderStatusQuery, [uid, lid], (err, results) => {
            if (err) {
              console.error('Failed to retrieve order status:', err.message);
              return res.status(500).json({ error: 'Failed to retrieve order status' });
            }

            if (results.length > 0) {
              const currentStatus = results[0].o_status;

              if (currentStatus === 1) {
                // ถ้าสถานะของคำสั่งซื้อเป็น 1 แล้ว จะไม่อัปเดตกระเป๋าเงิน
                return res.status(400).json({ error: 'Order already claimed' });
              }

              // ขั้นตอนที่ 4: อัปเดตยอดเงินในกระเป๋าของผู้ใช้
              const walletQuery = 'SELECT user_wallet FROM user WHERE uid = ?';
              db.query(walletQuery, [uid], (err, results) => {
                if (err) {
                  console.error('Failed to retrieve user wallet:', err.message);
                  return res.status(500).json({ error: 'Failed to retrieve user wallet' });
                }

                if (results.length > 0) {
                  const currentBalance = results[0].user_wallet;
                  const newBalance = currentBalance + rewardAmount; // เพิ่มเงินรางวัล

                  // อัปเดตยอดเงินในกระเป๋าของผู้ใช้
                  const updateQuery = 'UPDATE user SET user_wallet = ? WHERE uid = ?';
                  db.query(updateQuery, [newBalance, uid], (err, updateResults) => {
                    if (err) {
                      console.error('Failed to update balance:', err.message);
                      return res.status(500).json({ error: 'Failed to update balance' });
                    }

                    if (updateResults.affectedRows > 0) {
                      // อัปเดตสถานะของคำสั่งซื้อ
                      const statusUpdateQuery = 'UPDATE orders SET o_status = 1 WHERE uid = ? AND lid = ? AND o_status = 0';
                      db.query(statusUpdateQuery, [uid, lid], (err, statusUpdateResults) => {
                        if (err) {
                          console.error('Failed to update order status:', err.message);
                          return res.status(500).json({ error: 'Failed to update order status' });
                        }

                        if (statusUpdateResults.affectedRows > 0) {
                          res.status(200).json({ message: 'Balance and order status updated successfully', new_balance: newBalance });
                        } else {
                          res.status(404).json({ error: 'Order not found or status already updated' });
                        }
                      });
                    } else {
                      res.status(404).json({ error: 'User not found' });
                    }
                  });
                } else {
                  res.status(404).json({ error: 'User not found' });
                }
              });
            } else {
              res.status(404).json({ error: 'Order not found' });
            }
          });
        } else {
          res.status(404).json({ error: 'Prize not found' });
        }
      });
    } else {
      res.status(404).json({ error: 'Lottery not found' });
    }
  });
});

app.post('/check-email', (req, res) => {
  const { user_email } = req.body;

  if (!user_email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const sql = 'SELECT * FROM user WHERE user_email = ?';
  db.query(sql, [user_email], (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).send(err);
    }
    if (results.length > 0) {
      res.status(200).json({ exists: true });
    } else {
      res.status(200).json({ exists: false });
    }
  });
});

app.post('/purchaseLotto', (req, res) => {
  const { lid, lNumber, lPrice, lStatus } = req.body;

  // ตรวจสอบข้อมูลที่ส่งเข้ามาว่าครบถ้วนหรือไม่
  if (!lid || !lNumber || !lPrice || !lStatus) {
      return res.status(400).json({ message: 'Incomplete data' });
  }

  // สร้าง SQL สำหรับการ Insert
  const sql = 'INSERT INTO lotto (lid, l_number, l_price, l_status) VALUES (?, ?, ?, ?)';

  // ทำการ Insert ลงฐานข้อมูล
  db.query(sql, [lid, lNumber, lPrice, lStatus], (err, result) => {
      if (err) {
          console.error('Database insert error:', err);
          return res.status(500).json({ message: 'Database error', error: err });
      }
      // หากสำเร็จให้ตอบกลับไป
      res.status(201).json({ message: 'Lotto purchased successfully!', lid: result.insertId });
  });
});


app.put('/updateLotto', (req, res) => {
  const { lid, wid } = req.body;

  console.log("Received data for update:", req.body); // Print received data

  if (!lid || !wid) {
    return res.status(400).json({ message: 'Incomplete data' });
  }

  // Check if wid is 0 and enforce the limit
  if (wid === 0) {
    // Query to count the number of records with wid = 0
    const countQuery = 'SELECT COUNT(*) as count FROM lotto WHERE wid = 0';
    db.query(countQuery, (err, results) => {
      if (err) {
        console.error('Database query error:', err);
        return res.status(500).send(err);
      }

      const count = results[0].count;
      if (count >= 95) {
        return res.status(400).json({ message: 'Cannot update. Limit of 95 records with wid = 0 reached' });
      }

      // Proceed with the update if the limit is not reached
      updateLottoNumber(lid, wid, res);
    });
  } else {
    // For wid other than 0, validate if it is allowed
    const allowedWid = 5; // Define the allowed wid value(s)
    if (wid !== allowedWid) {
      return res.status(400).json({ message: 'Invalid wid value' });
    }

    // Proceed with the update if wid is allowed
    updateLottoNumber(lid, wid, res);
  }
});

// Function to handle the update operation
function updateLottoNumber(lid, wid, res) {
  const sql = 'UPDATE lotto SET wid = ? WHERE lid = ?';
  db.query(sql, [wid, lid], (err, result) => {
    if (err) {
      console.error('Database update error:', err);
      return res.status(500).send(err);
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Lotto not found' });
    }

    res.status(200).json({ message: `Lotto number updated successfully for id ${lid}` });
  });
}







app.delete('/resetLotto', (req, res) => {
  // Queries to delete data from the tables
  const deleteOrdersQuery = 'DELETE FROM orders';
  const deleteLotteryQuery = 'DELETE FROM lotto';
  const deleteUsersQuery = 'DELETE FROM user WHERE user_type != 1';

  // Begin a transaction
  db.beginTransaction(err => {
    if (err) {
      console.error('Transaction start failed:', err);
      return res.status(500).send({ error: 'Transaction start failed' });
    }

    // Delete data from the orders table
    db.query(deleteOrdersQuery, (err, results) => {
      if (err) {
        console.error('Failed to delete orders data:', err);
        return db.rollback(() => res.status(500).send({ error: 'Failed to delete orders data' }));
      }

      // Proceed to delete data from the lotto table
      db.query(deleteLotteryQuery, (err, results) => {
        if (err) {
          console.error('Failed to delete lottery data:', err);
          return db.rollback(() => res.status(500).send({ error: 'Failed to delete lottery data' }));
        }

        // Proceed to delete data from the user table
        db.query(deleteUsersQuery, (err, results) => {
          if (err) {
            console.error('Failed to delete user data:', err);
            return db.rollback(() => res.status(500).send({ error: 'Failed to delete user data' }));
          }

          // Commit the transaction
          db.commit(err => {
            if (err) {
              console.error('Transaction commit failed:', err);
              return db.rollback(() => res.status(500).send({ error: 'Transaction commit failed' }));
            }

            res.status(200).send({ success: 'All data deleted successfully' });
          });
        });
      });
    });
  });
});





app.post('/ordersHistory', (req, res) => {
  const { uid } = req.body;

  if (!uid) {
    return res.status(400).json({ error: 'Missing uid' });
  }

  // Retrieve orders and related reward data
  const query = `
    SELECT o.oid, o.lid, o.o_status, COALESCE(w.reward, 0) AS reward
FROM orders o
LEFT JOIN winner w ON o.lid = w.wid
LEFT JOIN lotto l ON w.wid = l.lid
WHERE o.uid = ?;
  `;
  
  db.query(query, [uid], (err, results) => {
    if (err) {
      console.error('Failed to retrieve order history:', err.message);
      return res.status(500).json({ error: 'Failed to retrieve order history' });
    }
    res.status(200).json(results);
  });
});





app.put('/updatemoney', (req, res) => {
  const { uid } = req.body; // รับ uid จาก request body

  if (!uid) {
    return res.status(400).json({ error: 'Missing uid' });
  }

  // ขั้นตอนที่ 1: เลือกยอดเงินปัจจุบันของผู้ใช้
  const selectQuery = 'SELECT user_wallet FROM user WHERE uid = ?';

  db.query(selectQuery, [uid], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to retrieve user wallet' });
    }

    if (results.length > 0) {
      const currentBalance = results[0].user_wallet; // ดึงยอดเงินปัจจุบัน

      // ตรวจสอบยอดเงินก่อนการหัก
      if (currentBalance < 100) {
        return res.status(400).json({ error: 'Insufficient funds' });
      }

      let new_balance = currentBalance - 100; // หักยอดเงิน

      // ขั้นตอนที่ 2: อัปเดตยอดเงินใหม่ในฐานข้อมูล
      const updateQuery = 'UPDATE user SET user_wallet = ? WHERE uid = ?';

      db.query(updateQuery, [new_balance, uid], (err, updateResults) => {
        if (err) {
          return res.status(500).json({ error: 'Failed to update balance' });
        }

        if (updateResults.affectedRows > 0) {
          res.status(200).json({ message: 'Balance updated successfully', new_balance });
        } else {
          res.status(404).json({ error: 'User not found' });
        }
      });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  });
});




// Middleware to protect routes
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    
    if (!token) return res.status(403).json({ message: 'Token required' });

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Protected Route
app.get('/profile', authenticateToken, (req, res) => {
    const sql = 'SELECT user_name, user_email FROM user WHERE uid = ?';
    db.query(sql, [req.user.uid], (err, results) => {
        if (err) return res.status(500).send(err);
        res.status(200).json(results[0]);
    });
});

// Start the server
const port = 3306;
var os = require("os");
const { log } = require('console');
var ip = "0.0.0.0";
var ips = os.networkInterfaces();
Object.keys(ips).forEach(function (_interface) {
  ips[_interface].forEach(function (_dev) {
    if (_dev.family === "IPv4" && !_dev.internal) ip = _dev.address;
  });
});

app.listen(port, () => {
  console.log(`Server is runing  on http://${ip}:${port}`);
});
