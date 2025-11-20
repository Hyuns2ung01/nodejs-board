const express = require('express');
const app = express();
const path = require('path');
const session = require('express-session'); // 세션 모듈

// DB 연결
const db = require('./db');

// 라우터 불러오기
const postsRouter = require('./routes/posts');
const authRouter = require('./routes/auth'); // [추가됨] 인증 라우터 불러오기

// EJS 템플릿 엔진 설정
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// POST 요청 및 정적 파일 설정
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 세션 설정
app.use(session({
    secret: 'secret_key_1234',
    resave: false,
    saveUninitialized: false
}));

// 로그인 사용자 정보
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

// 라우터 등록
app.use('/', authRouter);
app.use('/posts', postsRouter);

// 메인 URL > 게시판으로 리다이렉트
app.get('/', (req, res) => {
    res.redirect('/posts');
});

// 서버 실행
app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});