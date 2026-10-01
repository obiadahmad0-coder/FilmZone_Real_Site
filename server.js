const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const multer=require("multer");
const Database=require("better-sqlite3");
const path=require("path"),fs=require("fs");

const app=express(), PORT=process.env.PORT||3000;
const ROOT=__dirname, DATA=path.join(ROOT,"data"), UP=path.join(ROOT,"public","uploads"), MEDIA=path.join(ROOT,"public","media");
fs.mkdirSync(DATA,{recursive:true});fs.mkdirSync(UP,{recursive:true});fs.mkdirSync(MEDIA,{recursive:true});
const db=new Database(path.join(DATA,"filmzone.db"));
db.pragma("journal_mode = WAL");
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password TEXT,role TEXT DEFAULT 'admin');
CREATE TABLE IF NOT EXISTS titles(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,year INTEGER,type TEXT NOT NULL,genre TEXT,description TEXT,poster TEXT,video TEXT,download TEXT,rating REAL DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);
if(!db.prepare("SELECT 1 FROM users WHERE username=?").get("admin")){
 const hash=bcrypt.hashSync(process.env.ADMIN_PASSWORD||"ChangeMe123!",12);
 db.prepare("INSERT INTO users(username,password) VALUES(?,?)").run("admin",hash);
}
app.use(express.json({limit:"2mb"}));app.use(express.urlencoded({extended:true}));
app.use(session({secret:process.env.SESSION_SECRET||"change-this-secret",resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:"lax"}}));
app.use(express.static(path.join(ROOT,"public")));

function admin(req,res,next){if(req.session.user?.role==="admin")return next();res.status(401).json({error:"ورود مدیر لازم است"});}
const storage=multer.diskStorage({destination:(req,file,cb)=>cb(null,UP),filename:(req,file,cb)=>cb(null,Date.now()+"-"+file.originalname.replace(/[^a-zA-Z0-9._-]/g,"_"))});
const upload=multer({storage,limits:{fileSize:1024*1024*1024}});
app.post("/api/login",(req,res)=>{const u=db.prepare("SELECT * FROM users WHERE username=?").get(req.body.username);if(!u||!bcrypt.compareSync(req.body.password,u.password))return res.status(401).json({error:"نام کاربری یا رمز عبور نادرست است"});req.session.user={id:u.id,username:u.username,role:u.role};res.json({ok:true})});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));
app.get("/api/titles",(req,res)=>res.json(db.prepare("SELECT * FROM titles ORDER BY id DESC").all()));
app.post("/api/titles",admin,upload.fields([{name:"poster",maxCount:1},{name:"video",maxCount:1}]),(req,res)=>{
 const b=req.body,f=req.files||{}; const poster=f.poster?.[0]?"/uploads/"+f.poster[0].filename:(b.poster||"");
 const video=f.video?.[0]?"/uploads/"+f.video[0].filename:(b.video||"");
 const download=b.download||video;
 const info=db.prepare(`INSERT INTO titles(title,year,type,genre,description,poster,video,download,rating) VALUES(?,?,?,?,?,?,?,?,?)`)
 .run(b.title,Number(b.year)||0,b.type,b.genre||"",b.description||"",poster,video,download,Number(b.rating)||0);
 res.json({ok:true,id:info.lastInsertRowid});
});
app.put("/api/titles/:id",admin,(req,res)=>{const b=req.body;db.prepare(`UPDATE titles SET title=?,year=?,type=?,genre=?,description=?,poster=?,video=?,download=?,rating=? WHERE id=?`).run(b.title,Number(b.year)||0,b.type,b.genre||"",b.description||"",b.poster||"",b.video||"",b.download||"",Number(b.rating)||0,req.params.id);res.json({ok:true})});
app.delete("/api/titles/:id",admin,(req,res)=>{db.prepare("DELETE FROM titles WHERE id=?").run(req.params.id);res.json({ok:true})});
app.get("/admin",(req,res)=>res.sendFile(path.join(ROOT,"public","admin.html")));
app.listen(PORT,()=>console.log(`FilmZone running: http://localhost:${PORT}`));