const express = require('express');
const path = require('path');
const logger = require('morgan');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const mysql = require('mysql2');
const myConnection = require('express-myconnection');
const debug = require('debug')('app:server');
const ejs = require('ejs');
const flash = require('express-flash');





// Create Express app
const app = express();

// View engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Middleware setup
app.use(flash());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


// Session setup
app.use(session({
  secret: 'penguins@198',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true if using HTTPS
}));

// Database setup
const dbOptions = {
  host: 'localhost',
  user: 'brnnguyen25',
  port: 3306,
  password: 'Duwanggang1@',
  database: 'setup'
};
app.use(myConnection(mysql, dbOptions, 'single'));

// Middleware to check if user is admin
function isAdmin(req, res, next) {
  if (req.session.isAdmin) {
    return next();
  }
  req.session.message = 'Access denied - Admin privileges required';
  res.redirect('/login');
}

// Middleware to check if user is admin
function isSuperAdmin(req, res, next) {
  if (req.session.isSuperAdmin) {
    return next();
  }
  req.session.message = 'Access denied - Admin privileges required';
  res.redirect('/login');
}


// Routes
app.get('/', (req, res) => {
  res.render('index', { title: 'Home' });
});

// Login routes
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login', message: req.session.message });
  req.session.message = null; // Clear message after displaying
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Basic validation
  if (!username || !password) {
    req.session.message = 'Please enter both username and password';
    return res.redirect('/login');
  }

  // Check user in database
  req.getConnection((err, connection) => {
    if (err) throw err;

    connection.query(
      'SELECT * FROM Users WHERE username = ? AND password = ?',
      [username, password],
      (error, results) => {
        if (error) throw error;

        if (results.length > 0) {
          const user = results[0];
          req.session.user = user;
          req.session.userType = user.user_type; 
          req.session.university = user.university; // Store university in session

           // Add  flag to session
           req.session.user.isAdmin = user.user_type === 'Admin';      
           req.session.user.isSuperAdmin = user.user_type === 'SuperAdmin'; 

          // Redirect based on user_type
          switch (user.user_type) {
            case 'Student':
              return res.redirect('/dashboard'); // Student Dashboard
            case 'Admin':
              return res.redirect('/admin-dashboard'); // Admin Dashboard
            case 'SuperAdmin':
              return res.redirect('/super-dashboard'); // Super Admin Dashboard
            default:
              req.session.message = 'User role not recognized';
              return res.redirect('/login');
          }

        } else {
          req.session.message = 'Invalid username or password';
          res.redirect('/login');
        }
      }
    );
  });
});

// Registration routes
app.get('/register', (req, res) => {
  res.render('register', { title: 'Register', message: req.session.message });
  req.session.message = null;
});

app.post('/register', (req, res) => {
    const { name, email, username, password, confirmPassword, university, user_type} = req.body;

    // Basic validation
    if (!name|| !email || !username || !password || !confirmPassword || !university || !user_type) {
      req.session.message = 'Please fill all fields';
      return res.redirect('/register');
    }
    
    // Username validation: only letters and numbers
    const usernameRegex = /^[a-zA-Z0-9]+$/;
    if (!usernameRegex.test(username)) {
      req.session.message = 'Username must contain only letters and numbers';
      return res.redirect('/register');
    }
    
    // Password validation
    const passwordRegex = /^(?=.*[0-9])(?=.*[@#$%&])[a-zA-Z0-9@#$%&]{4,12}$/;
    if (!passwordRegex.test(password)) {
      req.session.message = 'Password must be 4-12 characters, contain at least one number and one special symbol (@#$%&)';
      return res.redirect('/register');
    }
    
    if (password !== confirmPassword) {
      req.session.message = 'Passwords do not match';
      return res.redirect('/register');
    }
    
    // Check if user exists
    req.getConnection((err, connection) => {
      if (err) throw err;
      
      connection.query(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        [username, email],
        (error, results) => {
          if (error) throw error;
          
          if (results.length > 0) {
            req.session.message = 'Username or email already exists';
            return res.redirect('/register');
          }
          
          // Create new user
          connection.query(
            'INSERT INTO users (name , email, username, password, university, user_type) VALUES (?, ?, ?, ?, ?, ?)', 
            [name, email, username, password, university, user_type],
            (insertError) => {
              if (insertError) throw insertError;
              
              req.session.message = 'Registration successful! Please login.';
              res.redirect('/login');
            }
          );
        }
      );
    });
    
  });

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Super Admin Routes
app.get('/super', (req, res) => {
    if (!req.session.user) {
      return res.redirect('/login');
    }
  
    req.getConnection((err, connection) => {
      if (err) throw err;
      
      // Get pending events (public only)
      connection.query(
        `SELECT e.*, u.username as creator_name 
         FROM events e 
         JOIN users u ON e.created_by = u.id 
         WHERE e.status = 'pending' AND e.event_type = 'public'`,
        (error, pendingEvents) => {
          if (error) throw error;
          
          // Get pending RSOs
          connection.query(
            `SELECT r.*, u.username as admin_name, u.email as admin_email, 
             (SELECT COUNT(*) FROM rsomembers WHERE rso_id = r.id) as member_count
             FROM rsos r 
             JOIN users u ON r.admin_id = u.id 
             WHERE r.status = 'pending'`,
            (error, pendingRSOs) => {
              if (error) throw error;
              
              res.render('super', {
                title: 'Super Admin Panel',
                user: req.session.user,
                pendingEvents: pendingEvents,
                pendingRSOs: pendingRSOs
              });
            }
          );
        }
      );
    });
  });
  
  // Approval routes
 
  app.post('/approve-event/:id', (req, res) => {
    if (!req.session.user || !req.session.user.isSuperAdmin) {
      return res.redirect('/login');
    }
    
    req.getConnection((err, connection) => {
      if (err) throw err;
      
      connection.query(
        'UPDATE events SET status = "approved" WHERE id = ?',
        [req.params.id],
        (error) => {
          if (error) throw error;
          res.redirect('/super');
        }
      );
    });
  });
  

  app.post('/reject-event/:id', (req, res) => {
    if (!req.session.user || !req.session.user.isSuperAdmin) {
      return res.redirect('/login');
    }
    
    req.getConnection((err, connection) => {
      if (err) throw err;
      
      connection.query(
        'UPDATE events SET status = "rejected" WHERE id = ?',
        [req.params.id],
        (error) => {
          if (error) throw error;
          res.redirect('/super');
        }
      );
    });
  });
  
 
  app.post('/approve-rso/:id', (req, res) => {
    if (!req.session.user || !req.session.user.isSuperAdmin) {
      return res.redirect('/login');
    }
    
    req.getConnection((err, connection) => {
      if (err) throw err;
      
      connection.query(
        'UPDATE rsos SET status = "approved" WHERE id = ?',
        [req.params.id],
        (error) => {
          if (error) throw error;
          res.redirect('/super');
        }
      );
    });
  });
  
  app.post('/reject-rso/:id', (req, res) => {
    if (!req.session.user || !req.session.user.isSuperAdmin) {
      return res.redirect('/login');
    }
    
    req.getConnection((err, connection) => {
      if (err) throw err;
      
      connection.query(
        'UPDATE rsos SET status = "rejected" WHERE id = ?',
        [req.params.id],
        (error) => {
          if (error) throw error;
          res.redirect('/super');
        }
      );
    });
  });


// Events routes
app.get('/events', (req, res) => {
  req.getConnection((err, connection) => {
    if (err) throw err;
    
    // Base query for public events (visible to everyone, must be approved)
    let query = `
        SELECT e.* 
        FROM events e
        WHERE e.event_type = 'public'
        AND e.status = 'approved'
    `;
    
    let queryParams = [];
    
    // If user is logged in, they can see more events
    if (req.session.user) {
      const user = req.session.user;
      
      // Add private events from the user's university (no approval required)
      query += `
          UNION
          SELECT e.* 
          FROM events e
          WHERE e.event_type = 'private' 
          AND e.university = ?
      `;
      queryParams.push(user.university);
      
      //  RSO events query 
      query += `
          UNION
          SELECT e.* 
          FROM events e
          JOIN rsomembers rm ON rm.rso_id = e.rso_id
          WHERE e.event_type = 'rso'
          AND rm.user_id = ?
      `;
      queryParams.push(user.id);
      
      // Admins and SuperAdmins can see all events from their university
      if (user.user_type === 'Admin' || user.user_type === 'SuperAdmin') {
        query += `
            UNION
            SELECT e.* 
            FROM events e
            WHERE e.university = ?
        `;
        queryParams.push(user.university);
      }
    }
    
    // Add ordering
    query += ' ORDER BY date, time';
    
    connection.query(query, queryParams, (error, results) => {
      if (error) throw error;
      
      res.render('events', { 
        title: 'Events', 
        user: req.session.user,
        events: results
      });
    });
  });
});
  
  app.post('/create-event', (req, res) => {
    if (!req.session.user || !req.session.user.isAdmin) {
      return res.redirect('/login');
    }
    
    const { name, category, description, date, time, location, contact_info, contact_email, event_type } = req.body;
    
    req.getConnection((err, connection) => {
      if (err) throw err;
      
      connection.query(
        'INSERT INTO events (name, category, description, date, time, location, contact_info, contact_email, event_type, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [name, category, description, date, time, location, contact_info, contact_email, event_type, req.session.user.id],
        (error) => {
          if (error) throw error;
          
          res.redirect('/events');
        }
      );
    });
  });


// Event View Route
app.get('/viewEvent/:id', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  req.getConnection((err, connection) => {
    if (err) throw err;
    
    // Get event details
    connection.query(
      `SELECT e.*, u.username as creator_name 
       FROM events e 
       JOIN users u ON e.created_by = u.id 
       WHERE e.id = ?`,
      [req.params.id],
      (error, eventResults) => {
        if (error) throw error;
        
        if (eventResults.length === 0) {
          return res.redirect('/events');
        }
        
        // Get comments for this event
        connection.query(
          `SELECT c.*, u.username, u.id as user_id 
           FROM comments c 
           JOIN users u ON c.user_id = u.id 
           WHERE c.event_id = ? 
           ORDER BY c.created_at DESC`,
          [req.params.id],
          (error, commentResults) => {
            if (error) throw error;
            
            // Get current user's rating for this event
            connection.query(
              `SELECT id, rating, text 
               FROM comments 
               WHERE event_id = ? AND user_id = ?`,
              [req.params.id, req.session.user.id],
              (error, userRatingResults) => {
                if (error) throw error;
                
                const event = eventResults[0];
                event.comments = commentResults;
                
                const userRating = userRatingResults.length > 0 ? {
                  id: userRatingResults[0].id,
                  rating: userRatingResults[0].rating,
                  comment: userRatingResults[0].text
                } : null;
                
                res.render('viewEvent', {
                  title: event.name,
                  user: req.session.user,
                  event: event,
                  userRating: userRating
                });
              }
            );
          }
        );
      }
    );
  });
});
  
  // Event Rating Route
  app.post('/rate-event/:id', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    
    // Block admins from rating (if desired)
    if (req.session.user.isAdmin || req.session.user.isSuperAdmin) {
      req.flash('error', 'Admins cannot rate events');
      return res.redirect(`/viewEvent/${req.params.id}`);
    }
  
    const { rating, comment } = req.body;
    
    // Validate rating (1-5)
    if (!rating || isNaN(rating) || rating < 1 || rating > 5) {
      req.flash('error', 'Please select a valid rating (1-5 stars)');
      return res.redirect(`/viewEvent/${req.params.id}`);
    }
    
    // Sanitize comment
    const sanitizedComment = comment ? comment.trim() : '';
    if (sanitizedComment.length > 500) {
      req.flash('error', 'Comment must be less than 500 characters');
      return res.redirect(`/viewEvent/${req.params.id}`);
    }
  
    req.getConnection((err, connection) => {
      if (err) {
        console.error(err);
        req.flash('error', 'Database error');
        return res.redirect(`/viewEvent/${req.params.id}`);
      }
      
      // Check if user already commented on this event
      connection.query(
        'SELECT id FROM comments WHERE event_id = ? AND user_id = ?',
        [req.params.id, req.session.user.id],
        (error, results) => {
          if (error) {
            console.error(error);
            req.flash('error', 'Database error');
            return res.redirect(`/viewEvent/${req.params.id}`);
          }
          
          if (results.length > 0) {
            // Update existing comment
            connection.query(
              'UPDATE comments SET rating = ?, text = ?, updated_at = NOW() WHERE id = ?',
              [rating, sanitizedComment, results[0].id],
              (error) => {
                if (error) {
                  console.error(error);
                  req.flash('error', 'Failed to update comment');
                } else {
                  req.flash('success', 'Comment updated successfully');
                }
                res.redirect(`/viewEvent/${req.params.id}`);
              }
            );
          } else {
            // Create new comment
            connection.query(
              'INSERT INTO comments (event_id, user_id, rating, text) VALUES (?, ?, ?, ?)',
              [req.params.id, req.session.user.id, rating, sanitizedComment],
              (error) => {
                if (error) {
                  console.error(error);
                  req.flash('error', 'Failed to add comment');
                } else {
                  req.flash('success', 'Comment added successfully');
                }
                res.redirect(`/viewEvent/${req.params.id}`);
              }
            );
          }
        }
      );
    });
  });

  // Delete Comment Route
app.post('/delete-comment/:id', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  
  req.getConnection((err, connection) => {
    if (err) {
      console.error(err);
      req.flash('error', 'Database error');
      return res.redirect('/events');
    }
    
    // First get the comment to verify ownership
    connection.query(
      'SELECT event_id, user_id FROM comments WHERE id = ?',
      [req.params.id],
      (error, results) => {
        if (error || results.length === 0) {
          console.error(error);
          req.flash('error', 'Comment not found');
          return res.redirect('/events');
        }
        
        const comment = results[0];
        
        // Verify user is the comment owner or an admin
        if (comment.user_id !== req.session.user.id && 
            !req.session.user.isAdmin && 
            !req.session.user.isSuperAdmin) {
          req.flash('error', 'You can only delete your own comments');
          return res.redirect(`/viewEvent/${comment.event_id}`);
        }
        
        // Delete the comment
        connection.query(
          'DELETE FROM comments WHERE id = ?',
          [req.params.id],
          (error) => {
            if (error) {
              console.error(error);
              req.flash('error', 'Failed to delete comment');
            } else {
              req.flash('success', 'Comment deleted successfully');
            }
            res.redirect(`/viewEvent/${comment.event_id}`);
          }
        );
      }
    );
  });
});

// Get Comment for Editing (AJAX-friendly)
app.get('/get-comment/:id', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  
  req.getConnection((err, connection) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    connection.query(
      'SELECT id, rating, text FROM comments WHERE id = ? AND user_id = ?',
      [req.params.id, req.session.user.id],
      (error, results) => {
        if (error) {
          console.error(error);
          return res.status(500).json({ error: 'Database error' });
        }
        
        if (results.length === 0) {
          return res.status(404).json({ error: 'Comment not found or not owned by user' });
        }
        
        res.json(results[0]);
      }
    );
  });
});

  // Universities Routes
app.get('/universities', (req, res) => {
    if (!req.session.user) {
      return res.redirect('/login');
    }
  
    req.getConnection((err, connection) => {
      if (err) throw err;
      
      connection.query(
        'SELECT name, location, description, num_students, contact_phone, contact_email FROM universities ORDER BY name',
        (error, universities) => {
          if (error) throw error;
          
          res.render('universities', {
            title: 'Universities',
            user: req.session.user,
            universities: universities
          });
        }
      );
    });
  });
  
  app.post('/create-university', (req, res) => {
    if (!req.session.user || !req.session.user.isSuperAdmin) {
      return res.redirect('/login');
    }
  
    const { name, location, description, num_students, contact_phone, contact_email } = req.body;
  
    req.getConnection((err, connection) => {
      if (err) throw err;
      
      connection.query(
        'INSERT INTO universities (name, location, description, num_students, contact_phone, contact_email) VALUES (?, ?, ?, ?, ?, ?)',
        [name, location, description, num_students, contact_phone, contact_email],
        (error) => {
          if (error) throw error;
          res.redirect('/universities');
        }
      );
    });
  });



  app.get('/organizations', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.redirect('/login');
  }
  req.getConnection((err, connection) => {
    if (err) {
      console.error('Connection error:', err);
      return res.status(500).send('Database connection failed.');
    }
    
//fixme
    const query = `
   SELECT 
    r.id, 
    r.name, 
    r.description,
    r.status,
    u.username AS admin_username,
    un.name AS university_name,
    COUNT(rm.user_id) AS MemberCount
  FROM 
    rsos r 
  LEFT JOIN 
    rsomembers rm ON r.id = rm.rso_id 
  JOIN
    Users u ON r.admin_id = u.id
  LEFT JOIN
    universities un ON r.university_id = un.id
  GROUP BY 
    r.id, r.name, r.description, r.status, u.username, un.name
    `;

    connection.query(query, (error, results) => {
      if (error) {
        console.error('Query error:', error);
        return res.status(500).send('Database query failed.');
      }

      res.render('organizations', {
        title: 'Organizations',
        user: req.session.user,
        orgs: results
      });
    });
  });
  
});


  // RSO View Route
  app.get('/viewRSO/:id', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    req.getConnection((err, connection) => {
        if (err) throw err;
        
        // Get RSO details
        connection.query(
          `SELECT r.*, u.username as admin_username, u.email as admin_email 
           FROM rsos r 
           JOIN Users u ON r.admin_id = u.id 
           WHERE r.id = ?`,
            [req.params.id],
            (error, rsoResults) => {
                if (error) throw error;
                
                if (rsoResults.length === 0) {
                    return res.redirect('/organizations');
                }
                
                // Check if current user is a member
                connection.query(
                  `SELECT 1 FROM rsomembers WHERE rso_id = ? AND user_id = ?`,
                    [req.params.id, req.session.user.id],
                    (error, isMemberResults) => {
                        if (error) throw error;
                        
                        const isMember = isMemberResults.length > 0;
                        
                        // Get members for this RSO (excluding admin)
                        connection.query(
                          `SELECT u.username, u.email 
                           FROM rsomembers rm 
                           JOIN Users u ON rm.user_id = u.id 
                           WHERE rm.rso_id = ? AND rm.user_id != ?`,
                            [req.params.id, rsoResults[0].admin_id],
                            (error, memberResults) => {
                                if (error) throw error;
                                
                                const rso = {
                                    ...rsoResults[0],
                                    admin: {
                                        username: rsoResults[0].admin_username,
                                        email: rsoResults[0].admin_email
                                    },
                                    members: memberResults,
                                    // Add this to match EJS expectation for members.length
                                    memberCount: memberResults.length
                                };
                                
                                res.render('viewRSO', {
                                    title: rso.name,
                                    user: req.session.user,
                                    rso: rso,
                                    isMember: isMember
                                });
                            }
                        );
                    }
                );
            }
        );
    });
});

// Join RSO Route
app.post('/rso/:id/join', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  req.getConnection((err, connection) => {
    if (err) throw err;
    
    // First check if user is already a member (more thorough check)
    connection.query(
      `SELECT 1 FROM rsomembers WHERE rso_id = ? AND user_id = ?`,
      [req.params.id, req.session.user.id],
      (error, results) => {
        if (error) {
          console.error('Database error:', error);
          return res.status(500).send('Database error');
        }
        
        if (results.length > 0) {
          // User is already a member - redirect back with message
          req.flash('error', 'You are already a member of this RSO');
          return res.redirect(`/rso/${req.params.id}`);
        }
        
        // Add user to RSO
        connection.query(
          `INSERT INTO rsomembers (rso_id, user_id) VALUES (?, ?)`,
          [req.params.id, req.session.user.id],
          (error) => {
            if (error) {
              if (error.errno === 1062) { // Duplicate entry error
                req.flash('error', 'You are already a member of this RSO');
                return res.redirect(`/rso/${req.params.id}`);
              }
              console.error('Database error:', error);
              return res.status(500).send('Database error');
            }
            req.flash('success', 'Successfully joined the RSO');
            res.redirect(`/rso/${req.params.id}`);
          }
        );
      }
    );
  });
});

// Leave RSO Route
app.post('/rso/:id/leave', (req, res) => {
  if (!req.session.user) {
      return res.redirect('/login');
  }

  req.getConnection((err, connection) => {
      if (err) throw err;
      
      // Remove user from RSO (but not if they're the admin)
      connection.query(
        `DELETE FROM rsomembers 
         WHERE rso_id = ? AND user_id = ? 
         AND user_id != (SELECT admin_id FROM rsos WHERE id = ?)`,
          [req.params.id, req.session.user.id, req.params.id],
          (error, results) => {
              if (error) throw error;
              res.redirect(`/viewRSO/${req.params.id}`);
          }
      );
  });
});

app.post('/create-rso', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  
  const { name, description, adminEmail, members } = req.body;
  
  // Validate input data
  if (!name || !description || !adminEmail) {
      return res.status(400).render('error', { 
          message: 'Name, description, and admin email are required',
          user: req.session.user 
      });
  }

  // Ensure members is an array (even if single member or empty)
  const membersArray = Array.isArray(members) ? members : 
                      (members ? [members] : []);

  // Validate all members have @ucf.edu emails
  const emailRegex = /^[^\s@]+@ucf\.edu$/i;
  const allMembers = [...membersArray, adminEmail]; // Include admin in validation
  
  for (const email of allMembers) {
      if (!emailRegex.test(email)) {
          return res.status(400).render('error', { 
              message: 'All members must have valid @ucf.edu email addresses',
              user: req.session.user 
          });
      }
  }

  req.getConnection((err, connection) => {
      if (err) {
          console.error(err);
          return res.status(500).render('error', { 
              message: 'Database connection error',
              user: req.session.user 
          });
      }

      // Check if members exist in database
      connection.query(
          'SELECT id, email FROM users WHERE email IN (?)',
          [allMembers],
          (error, results) => {
              if (error) {
                  console.error(error);
                  return res.status(500).render('error', { 
                      message: 'Database error',
                      user: req.session.user 
                  });
              }

              // Verify we found all members by comparing counts
              if (results.length !== allMembers.length) {
                  // Find which emails are missing
                  const foundEmails = results.map(r => r.email);
                  const missingEmails = allMembers.filter(email => !foundEmails.includes(email));
                  
                  return res.status(400).render('error', { 
                      message: `The following members do not exist in the system: ${missingEmails.join(', ')}`,
                      user: req.session.user 
                  });
              }

              // Create the RSO in database
              connection.beginTransaction(err => {
                  if (err) {
                      console.error(err);
                      return res.status(500).render('error', { 
                          message: 'Transaction error',
                          user: req.session.user 
                      });
                  }

                  // First insert the RSO
                  connection.query(
                      'INSERT INTO rsos (name, description, admin_id) VALUES (?, ?, (SELECT id FROM users WHERE email = ?))',
                      [name, description, adminEmail],
                      (error, results) => {
                          if (error) {
                              return connection.rollback(() => {
                                  console.error(error);
                                  res.status(500).render('error', { 
                                      message: 'Error creating RSO: ' + error.message,
                                      user: req.session.user 
                                  });
                              });
                          }

                          const rsoId = results.insertId;

                          // Then insert all members (excluding admin who is already the admin)
                          const memberEmails = membersArray.filter(email => email !== adminEmail);
                          if (memberEmails.length > 0) {
                              connection.query(
                                  'INSERT INTO rsomembers (rso_id, user_id) SELECT ?, id FROM users WHERE email IN (?)',
                                  [rsoId, memberEmails],
                                  (error) => {
                                      if (error) {
                                          return connection.rollback(() => {
                                              console.error(error);
                                              res.status(500).render('error', { 
                                                  message: 'Error adding members: ' + error.message,
                                                  user: req.session.user 
                                              });
                                          });
                                      }
                                      commitTransaction();
                                  }
                              );
                          } else {
                              commitTransaction();
                          }

                          function commitTransaction() {
                              connection.commit(err => {
                                  if (err) {
                                      return connection.rollback(() => {
                                          console.error(err);
                                          res.status(500).render('error', { 
                                              message: 'Transaction commit error',
                                              user: req.session.user 
                                          });
                                      });
                                  }

                                  req.flash('success', 'RSO created successfully! Awaiting approval.');
                                  res.redirect('/organizations');
                              });
                          }
                      }
                  );
              });
          }
      );
  });
});


// Protected dashboard route
app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.render('dashboard', { title: 'Dashboard', user: req.session.user });
});

// Protected super-dashboard route
app.get('/super-dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.render('super-dashboard', { title: 'Dashboard', user: req.session.user });
});

// Protected admin-dashboard route
app.get('/admin-dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.render('admin-dashboard', { title: 'Dashboard', user: req.session.user });
});



// Error handling
app.get('/error', (req, res) => {
  res.render('error', { title: 'Error' });
});
// 404 Error handling
app.use((req, res, next) => {
  res.status(404).render('error', { title: '404 - Not Found', message: 'Page not found' });
});

// General error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('error', { title: '500 - Server Error', message: 'Something went wrong' });
});

// Start server
app.listen(3000, () => {
  debug('Server is running on http://localhost:3000');
  console.log('Server is running on http://localhost:3000');
});

module.exports = app;
