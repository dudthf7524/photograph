const express = require('express')
const { Server } = require('http')
const app = express()
require('dotenv').config();
const {MongoClient, ObjectId} = require('mongodb');
const path = require('path');

app.use(express.json());
var cors = require('cors');
app.use(cors());

app.use(cors({
    origin: 'http://localhost:3000',  // 리액트 앱의 URL
    methods: ['GET', 'POST'],
    credentials: true,
}));

const bcrypt = require('bcrypt')
const passport = require('passport')
const LocalStrategy = require('passport-local')
const session = require('express-session')
const MongoStore = require('connect-mongo')

const date = new Date()
const formattedDate = new Intl.DateTimeFormat('ko-KR', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    weekday: 'long',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true
}).format(date);


  
let db;
const url = process.env.DB_URL;
new MongoClient(url).connect().then((client) =>{
    console.log('DB연결성공')
    db = client.db('photograph');
    app.listen(process.env.PORT, () => {
        console.log('http://localhost:8090 에서 서버 실행중')
    })
}).catch((err) =>{
    console.log(err)
})

app.use(passport.initialize())

app.use(session({
    secret: '암호화에 쓸 비번',
    resave : false, // 유저가 서버로 요청할 때마다 세션 갱신할건지
    saveUninitialized : false, // 로그인 안해도 세션 만들것인지
    cookie : {maxAge : 60 * 60 * 1000}, // 1시간 유지 세션 유효기간 설정 코드
  // 세션 데이터에 저장
    store: MongoStore.create({
      mongoUrl : process.env.DB_URL,
      dbName: 'photograph'
    })
  
  }))
app.use(passport.session()) 

app.use(express.static(path.join(__dirname, 'react-photograph/build')));

app.get('/', (req, res) => {
   
    res.sendFile(path.join(__dirname, 'react-photograph/build/index.html'));
})

app.get('/user/join', (req, res) => {
   
    res.sendFile(path.join(__dirname, 'react-photograph/build/index.html'));
})

app.get('/user/login', (req, res) => {
    console.log(req.user);
    res.sendFile(path.join(__dirname, 'react-photograph/build/index.html'));
})

app.post('/user/join', async(req, res) => {
    console.log(req.body)
    const date = new Date()
    const formattedDate = new Intl.DateTimeFormat('ko-KR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        weekday: 'long',
        hour: 'numeric',
        minute: '2-digit',
        hour12: true
    }).format(date);
    // 중복 아이디 확인
    const existingUser = await db.collection('user').findOne({ username: req.body.username });
    if (existingUser) {
        // 중복 아이디가 있을 경우 오류 메시지 반환
        return res.status(400).json({ message: '이미 존재하는 아이디입니다.' });
    }
    let password = await bcrypt.hash(req.body.password, 10);
    await db.collection('user').insertOne({
        nickname : req.body.nickname,
        username : req.body.username,
        password : password,
        joinDate : formattedDate
    });
    res.sendFile(path.join(__dirname, 'react-photograph/build/index.html'));
})

app.post('/user/login', async(req, res, next) =>{
    console.log(req.body)
    passport.authenticate('local', (error, user, info)=>{
        if(error) return res.status(500).json(error)
        if(!user) return res.status(401).json(info.message)
            req.logIn(user, (err) =>{
            if(err) return next(err)
                res.redirect('/')
        })
    })(req, res, next)

    
})

passport.use(new LocalStrategy(async (입력한아이디, 입력한비번, cb) => {
    
    let result = await db.collection('user').findOne({ username : 입력한아이디})
    
    if (!result) {
      return cb(null, false, { message: '아이디 DB에 없음' })
    }
    
    if (await bcrypt.compare(입력한비번, result.password)) {
      return cb(null, result)
    } else {
      return cb(null, false, { message: '비번불일치' });
    }
}))

//요청.login 사용하여 로그인 성공화면 세션 document 만들어서 쿠키를 유저에게 보내줌
passport.serializeUser((user, done) => {
    console.log(user)
    process.nextTick(() => {
        done(null, { id: user._id, username: user.username })
    })
})

//쿠키를 분석하는 코드
passport.deserializeUser(async (user, done) => {
    let result = await db.collection('user').findOne({_id : new ObjectId(user.id)})
    delete result.password
    
    process.nextTick(() => {
        return done(null, result)
    })
})




app.get('/user/logout', (request, response) => {
    request.logout((err) => { // request.logout()으로 세션 삭제
        if (err) { return response.status(500).send("로그아웃 오류"); }
        request.session.destroy(() => { // 세션 완전히 파기
            response.clearCookie('connect.sid'); // 세션 쿠키 삭제
            response.redirect('/'); // 홈 또는 로그인 페이지로 리디렉션
        });
    });
});

app.use(cors({
    origin: 'http://localhost:3000', // React 앱이 실행 중인 포트
    credentials: true // 쿠키 허용
}));
app.get('/user/auth', (req, res) => {
    console.log(req.user)
    res.json(req.user)
});

const { S3Client } = require('@aws-sdk/client-s3')
const multer = require('multer')
const multerS3 = require('multer-s3')
const s3 = new S3Client({
  region : 'ap-northeast-2',
  credentials : {
      accessKeyId : process.env.S3_KEY,
      secretAccessKey : process.env.S3_SECRET
  }
})

const upload = multer({
  storage: multerS3({
    s3: s3,
    bucket: 'photograph1',
    key: function (요청, file, cb) {
      cb(null, Date.now().toString()) //업로드시 파일명 변경가능
    }
  })
})

app.get('/post/write', (req, res) => {
    res.sendFile(path.join(__dirname, 'react-photograph/build/index.html'));
})

app.get('/post/list', (req, res) => {
   
    res.sendFile(path.join(__dirname, 'react-photograph/build/index.html'));
})

function isAuthenticated(req, res, next) {
  if (req.isAuthenticated() && req.user._id) {
      // 로그인된 상태
      return next();
  } else {
      // 로그인되지 않은 상태일 때 로그인 페이지로 리디렉션
      return res.status(401).json({ message: '로그인이 필요합니다.' });
  }
}

app.post('/post/write', isAuthenticated, upload.single('img'), async (req, res) =>{
    console.log(req.body)
    let category = req.body.category;
    let title = req.body.title;
    let content = req.body.content;
    let img = req.file.location;
    const formattedDates = new Intl.DateTimeFormat('ko-KR', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      weekday: 'long',
      hour: 'numeric',
      minute: '2-digit',
      hour12: true
  }).format(date);
    try{
        if(title == ''){
            응답.send('제목입력안했는데?')
        }else{
            await db.collection('post').insertOne({
                writerId : new ObjectId(req.user._id),
                category : category, 
                title : title, 
                content : content,
                img : img,
                writeDate : formattedDates
            })
            res.redirect('/user/join')   
        }
    }catch(e){
        console.log(e)
        응답.status(500).send('서버에러남')
    }
})

app.get('/api/list', async (req, res) => {
  const page = parseInt(req.query.page) || 1; // 클라이언트로부터 받은 페이지 번호 (기본값은 1)
  const limit = 10; // 페이지당 항목 수
  const skip = (page - 1) * limit; // 페이지에 맞게 건너뛸 항목 수
    try {
      const totalItems = await db.collection('post').countDocuments();
      const totalPages = Math.ceil(totalItems / limit);
      const result = await db.collection('post').aggregate([
        {
          $lookup: {
            from: 'user',            // 조인할 컬렉션 이름
            localField: 'writerId',   // post 컬렉션의 필드
            foreignField: '_id',      // user 컬렉션의 필드
            as: 'writerInfo'          // 조인 결과를 담을 필드 이름
          }
        },
        {
          $unwind: "$writerInfo"      // 배열 형태의 writerInfo를 펼쳐서 사용
        },
        {
          $sort: { writeDate: -1 }    // 날짜별 내림차순 정렬
        },
        {
          $project: {
            title: 1,
            content: 1,
            category: 1,
            writeDate: 1,
            img: 1,
            "writerInfo.nickname": 1  // 필요한 필드만 선택
          }
        },
        { $skip: skip },              // 현재 페이지에 맞게 항목 건너뛰기
        { $limit: limit }       
      ]).toArray();
  
      
      res.json({
        posts: result,
        totalPages,
        currentPage: page,
      });
    } catch (error) {
      console.error("Error fetching list:", error);
      res.status(500).json({ error: 'Failed to fetch list' });
    }
  });

app.get('/api/mylist', isAuthenticated, async (req, res) => {
  console.log(req.user._id)
  try {
    const result = await db.collection('post').aggregate([
      {
        $match: { writerId: new ObjectId(req.user._id) } // 해당 id의 게시물 필터링
      },
      {
        $lookup: {
          from: 'user',            // 조인할 컬렉션 이름
          localField: 'writerId',   // post 컬렉션의 필드
          foreignField: '_id',      // user 컬렉션의 필드
          as: 'writerInfo'          // 조인 결과를 담을 필드 이름
        }
      },
      {
        $sort: { writeDate: -1 }    // 날짜별 내림차순 정렬
      },
      {
        $unwind: "$writerInfo"      // 배열 형태의 writerInfo를 펼쳐서 사용
      },
      {
        $project: {
          title: 1,
          content: 1,
          category: 1,
          writeDate: 1,
          img: 1,
          "writerInfo.nickname": 1  // 필요한 필드만 선택
        }
      }
    ]).toArray();

    
    res.json(result);
  } catch (error) {
    console.error("Error fetching list:", error);
    res.status(500).json({ error: 'Failed to fetch list' });
  }
});

app.get('/api/post/detail/:id', async (req, res) => {
  console.log(req.params.id);
  try {
      const result = await db.collection('post').aggregate([
          {
              $match: { _id: new ObjectId(req.params.id) } // 해당 id의 게시물 필터링
          },
          {
              $lookup: {
                  from: 'user',             // 조인할 컬렉션 이름
                  localField: 'writerId',   // post 컬렉션의 필드
                  foreignField: '_id',      // user 컬렉션의 필드
                  as: 'writerInfo'          // 조인 결과를 담을 필드 이름
              }
          },
          {
              $unwind: "$writerInfo"       // 배열 형태의 writerInfo를 펼쳐서 사용
          },
          {
              $project: {
                  title: 1,
                  content: 1,
                  category: 1,
                  writeDate: 1,
                  img: 1,
                  "writerInfo.nickname": 1  // 필요한 필드만 선택
              }
          }
      ]).next();  // 배열 대신 첫 번째 결과 객체만 반환
      console.log(result)
      if (result) {
          res.json(result);  // 결과가 있다면 반환
      } else {
          res.status(404).send('Post not found');
      }
  } catch (error) {
      console.error("Error fetching post detail:", error);
      res.status(500).json({ error: 'Failed to fetch post detail' });
  }
});


app.post('/post/comment/:id', async (req, res) => {
  await db.collection('comment').insertOne({
    writerId : new ObjectId(req.user._id),
    parentId : new ObjectId(req.params.id),
    comment : req.body.comment,
    commentDate : formattedDate
  })
  res.redirect('/user/join')   
  
});

app.get('/api/post/comment/:id', async (req, res) => {
  console.log('넘어온 부모값')
  console.log(req.params.id)
  try {
    const result = await db.collection('comment').aggregate([
      {
        $match: { parentId: new ObjectId(req.params.id) } // 해당 id의 게시물 필터링
      },
      {
        $lookup: {
          from: 'user',            // 조인할 컬렉션 이름
          localField: 'writerId',   // comment 컬렉션의 필드
          foreignField: '_id',      // user 컬렉션의 필드
          as: 'writerInfo'          // 조인 결과를 담을 필드 이름
        }
      },
      {
        $unwind: "$writerInfo"      // 배열 형태의 writerInfo를 펼쳐서 사용
      },
      {
        $project: {
          comment: 1,
          commentDate: 1,
          "writerInfo.nickname": 1  // 필요한 필드만 선택
        }
      }
    ]).toArray();
    console.log('댓글 모음')
    console.log(result)
    res.json(result);
  } catch (error) {
    console.error("Error fetching list:", error);
    res.status(500).json({ error: 'Failed to fetch list' });
  }
});

// post 수정

const AWS = require('aws-sdk');

const s4 = new AWS.S3({
  accessKeyId: process.env.S3_KEY,   // 사용자 만들면서 지급받은 키값
  secretAccessKey: process.env.S3_SECRET
  ,
  region: 'ap-northeast-2'
})


app.get('/api/post/edit/:id', async (req, res) => {
  console.log(req.params.id);
  try {
    let result =await db.collection('post').findOne({_id : new ObjectId(req.params.id)})
   
      console.log(result)
      if (result) {
          res.json(result);  // 결과가 있다면 반환
      } else {
          res.status(404).send('Post not found');
      }
  } catch (error) {
      console.error("Error fetching post detail:", error);
      res.status(500).json({ error: 'Failed to fetch post detail' });
  }
});


app.put('/post/edit/:id', upload.single('img'), async (req, res) => {
  console.log(req.params.id);
  console.log(req.body)
  console.log(req.body.content)
  console.log(req.body.title)
  console.log(req.body.category)
  
  
  let result = await db.collection('post').findOne({_id : new ObjectId(req.params.id)})
  if(req.body.img === result.img && (!req.file || req.file.location === '')){
    console.log('이미지가 같다')
    await db.collection('post').updateOne({_id : new ObjectId(req.params.id)},{
    $set:{category : req.body.category, title : req.body.title, content : req.body.content}})
    res.sendFile(path.join(__dirname, 'react-photograph/build/index.html'));
  }else{
    if(result.img == null){
      let img = req.file.location;
      await db.collection('post').updateOne({_id : new ObjectId(req.params.id)},{
        $set:{
          category : req.body.category, 
          title : req.body.title, 
          content : req.body.content,
          img : img}})
        res.sendFile(path.join(__dirname, 'react-photograph/build/index.html'));
    }else{
      let img = req.file.location;
      console.log('이미지가 다르다')
      const url = result.img.split('/');
      s4.deleteObject({
        Bucket: 'photograph1', // 삭제하고 싶은 이미지가 있는 버킷 이름
        Key: url[3], // 삭제하고 싶은 이미지의 key 
      }, (err, data) => {
           if (err) console.log(err); // 실패 시 에러 메시지
           else console.log(data); // 성공 시 데이터 출력
      });
      await db.collection('post').updateOne({_id : new ObjectId(req.params.id)},{
      $set:{
        category : req.body.category, 
        title : req.body.title, 
        content : req.body.content,
        img : img}})
      res.sendFile(path.join(__dirname, 'react-photograph/build/index.html'));
    }
    

  }
  
  
 
 
});

app.delete('/api/post/delete/:id', async (req, res) => {
  console.log(req.params.id);

  
  let result =await db.collection('post').findOne({_id : new ObjectId(req.params.id)})
  let commentResult = await db.collection('comment').findOne({parentId : new ObjectId(req.params.id)})
  console.log(result.img)
  console.log(commentResult)
  const url = result.img.split('/');
  console.log(url[3])

  s4.deleteObject({
    Bucket: 'photograph1', // 삭제하고 싶은 이미지가 있는 버킷 이름
    Key: url[3], // 삭제하고 싶은 이미지의 key 
  }, (err, data) => {
       if (err) console.log(err); // 실패 시 에러 메시지
       else console.log(data); // 성공 시 데이터 출력
  });
  await db.collection('post').deleteOne( { _id : new ObjectId(req.params.id)} )
  await db.collection('comment').deleteMany( { parentId : new ObjectId(req.params.id)} )
  res.sendFile(path.join(__dirname, 'react-photograph/build/index.html'));
});

app.get('/user/mypage/auth' , async (req, res) =>{
 
  let result = await db.collection('user').findOne({_id : new ObjectId(req.user._id)})
 
  res.json(result)
})


app.put('/api/user/edit/', async (req, res) => {
  
  let password = await bcrypt.hash(req.body.password, 10);
  await db.collection('user').updateOne({_id : new ObjectId(req.user._id)},{
  $set:{nickname : req.body.nickname, password : password }})
  res.sendFile(path.join(__dirname, 'react-photograph/build/index.html'));
  
});

app.delete('/user/delete', async (req, res) =>{
  console.log(req.user._id)

  try {
    const userId = req.user._id;

    // 1. 사용자가 작성한 게시물이 있는지 확인
    const userPosts = await db.collection('post').find({ writerId: new ObjectId(userId) }).toArray();

    if (userPosts.length > 0) {
        // 게시물이 있으면 회원 탈퇴 불가 메시지 전송
        return res.status(400).json({ message: "게시물이 있어 회원탈퇴를 할 수 없습니다." });
    }

    // 2. 게시물이 없으면 회원 정보 삭제
    await db.collection('user').deleteOne({ _id: new ObjectId(userId) });

    // 3. 로그아웃 및 세션 정리
    req.logout((err) => {
        if (err) return res.status(500).send("로그아웃 오류 발생");

        req.session.destroy(() => {
            res.clearCookie('connect.sid');
            res.sendStatus(200);
        });
    });
  } catch (error) {
      console.error("회원 탈퇴 중 오류:", error);
      res.status(500).json({ error: '회원 탈퇴 실패' });
  }
   
});

app.get('/api/post/category/:id', async (req, res) =>{ 
  try {
    const result = await db.collection('post').aggregate([
      {
        $match: { category: req.params.id } // 해당 id의 게시물 필터링
      },
      {
        $lookup: {
          from: 'user',            // 조인할 컬렉션 이름
          localField: 'writerId',   // post 컬렉션의 필드
          foreignField: '_id',      // user 컬렉션의 필드
          as: 'writerInfo'          // 조인 결과를 담을 필드 이름
        }
      },
      {
        $unwind: "$writerInfo"      // 배열 형태의 writerInfo를 펼쳐서 사용
      },
      {
        $sort: { writeDate: -1 }    // 날짜별 내림차순 정렬
      },
      {
        $project: {
          title: 1,
          content: 1,
          category: 1,
          writeDate: 1,
          img: 1,
          "writerInfo.nickname": 1  // 필요한 필드만 선택
        }
      }
    ]).toArray();

    console.log(result)
    res.json(result);
  } catch (error) {
    console.error("Error fetching list:", error);
    res.status(500).json({ error: 'Failed to fetch list' });
  }
});

app.get('/api/post/new', async (req, res) =>{ 
  const limit = 3;
  const result = await db.collection('post').aggregate([
    {
      $lookup: {
        from: 'user',            // 조인할 컬렉션 이름
        localField: 'writerId',   // post 컬렉션의 필드
        foreignField: '_id',      // user 컬렉션의 필드
        as: 'writerInfo'          // 조인 결과를 담을 필드 이름
      }
    },
    {
      $unwind: "$writerInfo"      // 배열 형태의 writerInfo를 펼쳐서 사용
    },
    {
      $sort: { writeDate: -1 }    // 날짜별 내림차순 정렬
    },
    {
      $project: {
        title: 1,
        content: 1,
        category: 1,
        writeDate: 1,
        img: 1,
        "writerInfo.nickname": 1  // 필요한 필드만 선택
      }
    },
    { $limit: limit }       
  ]).toArray();
  
  res.json(result)

});

app.get('*', function (req, res) {
    res.sendFile(path.join(__dirname, 'react-photograph/build/index.html'));
});





