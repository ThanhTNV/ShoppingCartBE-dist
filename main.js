/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ([
/* 0 */,
/* 1 */
/***/ ((module) => {

module.exports = require("@nestjs/core");

/***/ }),
/* 2 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppModule = void 0;
const common_1 = __webpack_require__(3);
const app_controller_1 = __webpack_require__(4);
const app_service_1 = __webpack_require__(5);
const users_module_1 = __webpack_require__(6);
const config_1 = __webpack_require__(12);
const database_module_1 = __webpack_require__(19);
const database_service_1 = __webpack_require__(11);
const products_module_1 = __webpack_require__(21);
const orders_module_1 = __webpack_require__(37);
let AppModule = class AppModule {
    constructor(databaseService) {
        this.databaseService = databaseService;
        this.databaseService.connect();
    }
};
exports.AppModule = AppModule;
exports.AppModule = AppModule = __decorate([
    (0, common_1.Module)({
        imports: [
            users_module_1.UsersModule,
            config_1.ConfigModule.forRoot({
                envFilePath: '.env',
                isGlobal: true,
            }),
            database_module_1.DatabaseModule,
            products_module_1.ProductsModule,
            orders_module_1.OrdersModule,
        ],
        controllers: [app_controller_1.AppController],
        providers: [app_service_1.AppService],
    }),
    __metadata("design:paramtypes", [typeof (_a = typeof database_service_1.DatabaseService !== "undefined" && database_service_1.DatabaseService) === "function" ? _a : Object])
], AppModule);


/***/ }),
/* 3 */
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),
/* 4 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppController = void 0;
const common_1 = __webpack_require__(3);
const app_service_1 = __webpack_require__(5);
let AppController = class AppController {
    constructor(appService) {
        this.appService = appService;
    }
    getHello() {
        return this.appService.getHello();
    }
};
exports.AppController = AppController;
__decorate([
    (0, common_1.Get)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", String)
], AppController.prototype, "getHello", null);
exports.AppController = AppController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [typeof (_a = typeof app_service_1.AppService !== "undefined" && app_service_1.AppService) === "function" ? _a : Object])
], AppController);


/***/ }),
/* 5 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppService = void 0;
const common_1 = __webpack_require__(3);
let AppService = class AppService {
    getHello() {
        return 'Hello World!';
    }
};
exports.AppService = AppService;
exports.AppService = AppService = __decorate([
    (0, common_1.Injectable)()
], AppService);


/***/ }),
/* 6 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersModule = void 0;
const common_1 = __webpack_require__(3);
const users_controller_1 = __webpack_require__(7);
const users_service_1 = __webpack_require__(8);
const database_module_1 = __webpack_require__(19);
const utils_module_1 = __webpack_require__(20);
const jwt_1 = __webpack_require__(14);
let UsersModule = class UsersModule {
};
exports.UsersModule = UsersModule;
exports.UsersModule = UsersModule = __decorate([
    (0, common_1.Module)({
        imports: [database_module_1.DatabaseModule, utils_module_1.UtilsModule, jwt_1.JwtModule],
        controllers: [users_controller_1.UsersController],
        providers: [users_service_1.UsersService],
        exports: [users_service_1.UsersService],
    })
], UsersModule);


/***/ }),
/* 7 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersController = void 0;
const common_1 = __webpack_require__(3);
const users_service_1 = __webpack_require__(8);
const users_requests_1 = __webpack_require__(15);
const swagger_1 = __webpack_require__(16);
let UsersController = class UsersController {
    constructor(usersService) {
        this.usersService = usersService;
    }
    async login(body) {
        const { email, password } = body;
        const result = await this.usersService.login({ email, password });
        if (!result) {
            throw new common_1.UnauthorizedException('Invalid email or password');
        }
        return result;
    }
    async register(body) {
        const { password, confirm_password } = body;
        if (password !== confirm_password) {
            throw new common_1.UnprocessableEntityException('Passwords do not match');
        }
        const { email } = body;
        const isExists = await this.usersService.checkEmailExists(email);
        if (isExists) {
            throw new common_1.UnprocessableEntityException('Email already exists');
        }
        const result = await this.usersService.register(body);
        return result;
    }
};
exports.UsersController = UsersController;
__decorate([
    (0, common_1.Post)('login'),
    (0, swagger_1.ApiBody)({ type: users_requests_1.LoginReqBody, description: 'Login Data' }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'User logged in' }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Invalid email or password' }),
    __param(0, (0, common_1.Body)(new common_1.ValidationPipe())),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof users_requests_1.LoginReqBody !== "undefined" && users_requests_1.LoginReqBody) === "function" ? _b : Object]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "login", null);
__decorate([
    (0, common_1.Post)('register'),
    (0, swagger_1.ApiBody)({ type: users_requests_1.RegisterReqBody, description: 'Register Data' }),
    (0, swagger_1.ApiResponse)({ status: 201, description: 'User registered' }),
    (0, swagger_1.ApiResponse)({ status: 422, description: 'Invalid input' }),
    __param(0, (0, common_1.Body)(new common_1.ValidationPipe())),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof users_requests_1.RegisterReqBody !== "undefined" && users_requests_1.RegisterReqBody) === "function" ? _c : Object]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "register", null);
exports.UsersController = UsersController = __decorate([
    (0, common_1.Controller)('users'),
    __metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object])
], UsersController);


/***/ }),
/* 8 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersService = void 0;
const common_1 = __webpack_require__(3);
const users_schemas_1 = __webpack_require__(9);
const database_service_1 = __webpack_require__(11);
const crypto_service_1 = __webpack_require__(13);
const jwt_1 = __webpack_require__(14);
const config_1 = __webpack_require__(12);
const mongodb_1 = __webpack_require__(10);
let UsersService = class UsersService {
    constructor(databaseService, cryptoService, jwtService, configService) {
        this.databaseService = databaseService;
        this.cryptoService = cryptoService;
        this.jwtService = jwtService;
        this.configService = configService;
    }
    async generateTokens(user) {
        const [access_token, refresh_token] = await Promise.all([
            this.jwtService.signAsync({ sub: user._id }, {
                expiresIn: this.configService.get('ACCESS_TOKEN_EXPIRES_IN'),
                algorithm: 'HS256',
                secret: this.configService.get('ACCESS_TOKEN_SECRET'),
            }),
            this.jwtService.signAsync({ sub: user._id }, {
                expiresIn: this.configService.get('REFRESH_TOKEN_EXPIRES_IN'),
                algorithm: 'HS256',
                secret: this.configService.get('REFRESH_TOKEN_SECRET'),
            }),
        ]);
        return { access_token, refresh_token };
    }
    async login(payload) {
        const { email, password } = payload;
        const passwordHash = await this.cryptoService.hashPassword(password);
        const result = await this.databaseService.users.findOne({ email });
        if (!result || result.password !== passwordHash) {
            return null;
        }
        const { access_token, refresh_token } = await this.generateTokens({
            _id: result._id.toString(),
        });
        return { access_token, refresh_token };
    }
    async register(payload) {
        const result = await this.databaseService.users.insertOne(new users_schemas_1.User({
            ...payload,
            date_of_birth: new Date(payload.date_of_birth),
            password: await this.cryptoService.hashPassword(payload.password),
        }));
        const { access_token, refresh_token } = await this.generateTokens({
            _id: result.insertedId.toString(),
        });
        return { access_token, refresh_token };
    }
    async checkEmailExists(email) {
        const user = await this.databaseService.users.findOne({ email });
        return Boolean(user);
    }
    async checkUserExists(user_id) {
        const user = await this.databaseService.users.findOne({
            _id: new mongodb_1.ObjectId(user_id),
        });
        return Boolean(user);
    }
};
exports.UsersService = UsersService;
exports.UsersService = UsersService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof database_service_1.DatabaseService !== "undefined" && database_service_1.DatabaseService) === "function" ? _a : Object, typeof (_b = typeof crypto_service_1.CryptoService !== "undefined" && crypto_service_1.CryptoService) === "function" ? _b : Object, typeof (_c = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _c : Object, typeof (_d = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _d : Object])
], UsersService);


/***/ }),
/* 9 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.User = void 0;
const mongodb_1 = __webpack_require__(10);
var UserVerifyType;
(function (UserVerifyType) {
    UserVerifyType[UserVerifyType["UNVERIFIED"] = 0] = "UNVERIFIED";
    UserVerifyType[UserVerifyType["VERIFIED"] = 1] = "VERIFIED";
})(UserVerifyType || (UserVerifyType = {}));
var USER_ROLE;
(function (USER_ROLE) {
    USER_ROLE[USER_ROLE["ADMIN"] = 0] = "ADMIN";
    USER_ROLE[USER_ROLE["STAFF"] = 1] = "STAFF";
    USER_ROLE[USER_ROLE["USER"] = 2] = "USER";
})(USER_ROLE || (USER_ROLE = {}));
class User {
    constructor(user) {
        this._id = user._id || new mongodb_1.ObjectId();
        this.name = user.name;
        this.email = user.email;
        this.password = user.password;
        this.date_of_birth = user.date_of_birth;
        this.created_at = user.created_at || new Date();
        this.updated_at = user.updated_at || new Date();
        this.email_verify_token = user.email_verify_token || '';
        this.reset_password_token = user.reset_password_token || '';
        this.verify = user.verify || UserVerifyType.UNVERIFIED;
        this.bio = user.bio || '';
        this.profile_picture_url = user.profile_picture_url || '';
        this.website = user.website || '';
        this.location = user.location || '';
        this.role = user.role || USER_ROLE.USER;
    }
}
exports.User = User;


/***/ }),
/* 10 */
/***/ ((module) => {

module.exports = require("mongodb");

/***/ }),
/* 11 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.DatabaseService = void 0;
const mongodb_1 = __webpack_require__(10);
const common_1 = __webpack_require__(3);
const config_1 = __webpack_require__(12);
let DatabaseService = class DatabaseService {
    constructor(configService) {
        this.configService = configService;
        this.uri = `mongodb+srv://${configService.get('DB_USERNAME')}:${configService.get('DB_PASSWORD')}@shoppingcartcluster.z2tjc.mongodb.net/?retryWrites=true&w=majority&appName=ShoppingCartCluster`;
        this.client = new mongodb_1.MongoClient(this.uri);
        this.db = this.client.db('ShoppingCartDB_clone');
    }
    async connect() {
        await this.client.connect();
        await this.db.command({ ping: 1 });
        console.log('Connected to database');
    }
    get users() {
        return this.db.collection(process.env.DB_USERS_COLLECTION);
    }
    get products() {
        return this.db.collection(process.env.DB_PRODUCTS_COLLECTION);
    }
    get product_instances() {
        return this.db.collection(process.env.DB_PRODUCT_ITEMS_COLLECTION);
    }
    get categories() {
        return this.db.collection(process.env.DB_CATEGORIES_COLLECTION);
    }
    get orders() {
        return this.db.collection(process.env.DB_ORDERS_COLLECTION);
    }
    get order_items() {
        return this.db.collection(process.env.DB_ORDER_ITEMS_COLLECTION);
    }
};
exports.DatabaseService = DatabaseService;
exports.DatabaseService = DatabaseService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object])
], DatabaseService);


/***/ }),
/* 12 */
/***/ ((module) => {

module.exports = require("@nestjs/config");

/***/ }),
/* 13 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CryptoService = void 0;
const common_1 = __webpack_require__(3);
const config_1 = __webpack_require__(12);
let CryptoService = class CryptoService {
    constructor(configService) {
        this.configService = configService;
    }
    async sha256(content) {
        const res = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content));
        return Array.from(new Uint8Array(res))
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('');
    }
    async hashPassword(password) {
        return this.sha256(password + this.configService.get('PASSWORD_SECRET'));
    }
};
exports.CryptoService = CryptoService;
exports.CryptoService = CryptoService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object])
], CryptoService);


/***/ }),
/* 14 */
/***/ ((module) => {

module.exports = require("@nestjs/jwt");

/***/ }),
/* 15 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LoginReqBody = exports.RegisterReqBody = void 0;
const swagger_1 = __webpack_require__(16);
const class_validator_1 = __webpack_require__(17);
const match_decorator_1 = __webpack_require__(18);
class RegisterReqBody {
}
exports.RegisterReqBody = RegisterReqBody;
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'name',
        description: 'Name of the user',
        example: 'John Doe',
        type: 'string',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], RegisterReqBody.prototype, "name", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'email',
        description: 'Email of the user',
        example: 'abcxyz@example.co',
        type: 'string',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsEmail)(),
    __metadata("design:type", String)
], RegisterReqBody.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'password',
        description: 'Password of the user',
        example: 'Password@123',
        type: 'string',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsStrongPassword)({
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1,
    }, {
        message: 'password requires at least 8 characters, 1 lowercase letter, 1 uppercase letter, 1 number, and 1 symbol',
    }),
    __metadata("design:type", String)
], RegisterReqBody.prototype, "password", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'confirm_password',
        description: 'Confirm Password of the user',
        example: 'Password@123',
        type: 'string',
    }),
    (0, match_decorator_1.Match)('password', { message: 'confirm password does not match password' }),
    __metadata("design:type", String)
], RegisterReqBody.prototype, "confirm_password", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'date_of_birth',
        description: 'Date of Birth of the user',
        example: '2000-01-01',
        type: 'string',
    }),
    (0, class_validator_1.IsISO8601)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], RegisterReqBody.prototype, "date_of_birth", void 0);
class LoginReqBody {
}
exports.LoginReqBody = LoginReqBody;
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'email',
        description: 'Email of the user',
        type: 'string',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsEmail)(),
    __metadata("design:type", String)
], LoginReqBody.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'password',
        description: 'Password of the user',
        type: 'string',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], LoginReqBody.prototype, "password", void 0);


/***/ }),
/* 16 */
/***/ ((module) => {

module.exports = require("@nestjs/swagger");

/***/ }),
/* 17 */
/***/ ((module) => {

module.exports = require("class-validator");

/***/ }),
/* 18 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MatchConstraint = void 0;
exports.Match = Match;
const class_validator_1 = __webpack_require__(17);
function Match(property, validationOptions) {
    return (object, propertyName) => {
        (0, class_validator_1.registerDecorator)({
            target: object.constructor,
            propertyName,
            options: validationOptions,
            constraints: [property],
            validator: MatchConstraint,
        });
    };
}
let MatchConstraint = class MatchConstraint {
    validate(value, args) {
        const [relatedPropertyName] = args.constraints;
        const relatedValue = args.object[relatedPropertyName];
        return value === relatedValue;
    }
};
exports.MatchConstraint = MatchConstraint;
exports.MatchConstraint = MatchConstraint = __decorate([
    (0, class_validator_1.ValidatorConstraint)({ name: 'Match' })
], MatchConstraint);


/***/ }),
/* 19 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.DatabaseModule = void 0;
const common_1 = __webpack_require__(3);
const database_service_1 = __webpack_require__(11);
const config_1 = __webpack_require__(12);
let DatabaseModule = class DatabaseModule {
};
exports.DatabaseModule = DatabaseModule;
exports.DatabaseModule = DatabaseModule = __decorate([
    (0, common_1.Module)({
        imports: [config_1.ConfigModule.forRoot({
                envFilePath: '.env',
            })],
        providers: [database_service_1.DatabaseService],
        exports: [database_service_1.DatabaseService],
    })
], DatabaseModule);


/***/ }),
/* 20 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UtilsModule = void 0;
const common_1 = __webpack_require__(3);
const config_1 = __webpack_require__(12);
const crypto_service_1 = __webpack_require__(13);
let UtilsModule = class UtilsModule {
};
exports.UtilsModule = UtilsModule;
exports.UtilsModule = UtilsModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({
                envFilePath: ['.env'],
            }),
        ],
        providers: [crypto_service_1.CryptoService],
        exports: [crypto_service_1.CryptoService],
    })
], UtilsModule);


/***/ }),
/* 21 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ProductsModule = void 0;
const common_1 = __webpack_require__(3);
const products_service_1 = __webpack_require__(22);
const products_controller_1 = __webpack_require__(24);
const guard_module_1 = __webpack_require__(32);
const jwt_1 = __webpack_require__(14);
const config_1 = __webpack_require__(12);
const database_module_1 = __webpack_require__(19);
const categories_controller_1 = __webpack_require__(34);
const categories_service_1 = __webpack_require__(28);
let ProductsModule = class ProductsModule {
};
exports.ProductsModule = ProductsModule;
exports.ProductsModule = ProductsModule = __decorate([
    (0, common_1.Module)({
        imports: [
            guard_module_1.GuardModule,
            jwt_1.JwtModule,
            config_1.ConfigModule.forRoot({
                envFilePath: ['.env'],
            }),
            database_module_1.DatabaseModule,
        ],
        controllers: [products_controller_1.ProductsController, categories_controller_1.CategoriesController],
        providers: [products_service_1.ProductsService, categories_service_1.CategoriesService],
        exports: [products_service_1.ProductsService, categories_service_1.CategoriesService],
    })
], ProductsModule);


/***/ }),
/* 22 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ProductsService = void 0;
const common_1 = __webpack_require__(3);
const database_service_1 = __webpack_require__(11);
const products_schemas_1 = __webpack_require__(23);
const mongodb_1 = __webpack_require__(10);
let ProductsService = class ProductsService {
    constructor(database) {
        this.database = database;
    }
    async insertProduct(createProductDto) {
        const result = await this.database.products.insertOne(new products_schemas_1.Product({
            ...createProductDto,
            category_id: createProductDto.category_id.map((id) => new mongodb_1.ObjectId(id)),
        }));
        return result;
    }
    async findAllProducts() {
        return await this.database.products.find().toArray();
    }
    async findProduct(id) {
        return await this.database.products.findOne({ _id: new mongodb_1.ObjectId(id) });
    }
    async findModelOfProduct(model) {
        return await this.database.products.findOne({ model });
    }
    async updateProduct({ id, updateProductDto, }) {
        const { category_id } = updateProductDto;
        const result = await this.database.products.findOneAndUpdate({ _id: new mongodb_1.ObjectId(id) }, {
            $set: {
                ...updateProductDto,
                category_id: category_id.map((id) => new mongodb_1.ObjectId(id)),
                updated_at: new Date(),
            },
        }, { returnDocument: 'after' });
        return result;
    }
    async insertProductInstance({ product_id, productInstance, }) {
        const result = await this.database.product_instances.insertOne(new products_schemas_1.ProductInstance({
            ...productInstance,
            product_id: new mongodb_1.ObjectId(product_id),
        }));
        return result;
    }
    async findAllProductInstances(product_id) {
        const result = await this.database.product_instances
            .find({ product_id: new mongodb_1.ObjectId(product_id) })
            .toArray();
        return result;
    }
    async findProductInstance({ _id, product_id, }) {
        if (!product_id) {
            return await this.database.product_instances.findOne({
                _id: new mongodb_1.ObjectId(_id),
            });
        }
        return await this.database.product_instances.findOne({
            _id: new mongodb_1.ObjectId(_id),
            product_id: new mongodb_1.ObjectId(product_id),
        });
    }
    async findExistProductInstance({ product_id, productInstance, }) {
        const result = await this.database.product_instances.findOne({
            ...productInstance,
            product_id: new mongodb_1.ObjectId(product_id),
        });
        return result;
    }
    async updateProductInstance({ id, updateProductInstanceDto, }) {
        const result = await this.database.product_instances.findOneAndUpdate({ _id: new mongodb_1.ObjectId(id) }, {
            ...updateProductInstanceDto,
            updated_at: new Date(),
        }, { returnDocument: 'after' });
        return result;
    }
};
exports.ProductsService = ProductsService;
exports.ProductsService = ProductsService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof database_service_1.DatabaseService !== "undefined" && database_service_1.DatabaseService) === "function" ? _a : Object])
], ProductsService);


/***/ }),
/* 23 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ProductInstance = exports.Product = void 0;
const mongodb_1 = __webpack_require__(10);
class Product {
    constructor(product) {
        this._id = product._id || new mongodb_1.ObjectId();
        this.model = product.model;
        this.category_id = product.category_id;
        this.created_at = product.created_at || new Date();
        this.updated_at = product.updated_at || new Date();
        this.description = product.description;
    }
}
exports.Product = Product;
class ProductInstance {
    constructor(productInstance) {
        this._id = productInstance._id || new mongodb_1.ObjectId();
        this.product_id = productInstance.product_id;
        this.name = productInstance.name;
        this.price = productInstance.price;
        this.color = productInstance.color;
        this.stock = productInstance.stock;
        this.created_at = productInstance.created_at || new Date();
        this.updated_at = productInstance.updated_at || new Date();
    }
}
exports.ProductInstance = ProductInstance;


/***/ }),
/* 24 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ProductsController = void 0;
const common_1 = __webpack_require__(3);
const products_service_1 = __webpack_require__(22);
const create_product_dto_1 = __webpack_require__(25);
const update_product_dto_1 = __webpack_require__(26);
const categories_service_1 = __webpack_require__(28);
const paramsValidation_pipe_1 = __webpack_require__(30);
const swagger_1 = __webpack_require__(16);
const querysValidation_pipe_1 = __webpack_require__(31);
let ProductsController = class ProductsController {
    constructor(productsService, categoriesService) {
        this.productsService = productsService;
        this.categoriesService = categoriesService;
    }
    async findAll() {
        const products = await this.productsService.findAllProducts();
        const products_id = products.map(({ _id }) => _id.toString());
        const productInstances = await Promise.all(products_id.map((id) => this.productsService.findAllProductInstances(id)));
        return products.map((product, index) => ({
            ...product,
            productInstances: productInstances[index],
        }));
    }
    async findOne(id, product_instance_id) {
        const product = await this.productsService.findProduct(id);
        if (!product) {
            throw new common_1.NotFoundException(`Product with ID ${id} not found`);
        }
        if (!product_instance_id) {
            const productInstances = await this.productsService.findAllProductInstances(id);
            return { ...product, productInstances };
        }
        else {
            const productInstance = await this.productsService.findProductInstance({
                product_id: id,
                _id: product_instance_id,
            });
            if (!productInstance) {
                throw new common_1.NotFoundException(`Product instance with ID ${product_instance_id} not found`);
            }
            return productInstance;
        }
    }
    async create(createProductDto) {
        const { model, category_id } = createProductDto;
        const isExists = await this.productsService.findModelOfProduct(model);
        if (isExists) {
            throw new common_1.UnprocessableEntityException('Model already exists');
        }
        const Categories = await Promise.all(category_id.map((id) => this.categoriesService.findCategory(id)));
        const isNotExists = Categories.some((category) => !category);
        if (isNotExists) {
            const category_id_not_found = Categories.find((category) => !category)._id.toString();
            throw new common_1.NotFoundException(`Category with ID ${category_id_not_found} not found`);
        }
        return await this.productsService.insertProduct(createProductDto);
    }
    async createItem(id, productInstance) {
        const isExists = await this.productsService.findProduct(id);
        if (!isExists) {
            throw new common_1.NotFoundException(`Product with ID ${id} not found`);
        }
        const isExistsInstance = await this.productsService.findExistProductInstance({
            product_id: id,
            productInstance,
        });
        if (isExistsInstance) {
            throw new common_1.UnprocessableEntityException('Product Instance already exists');
        }
        const result = await this.productsService.insertProductInstance({
            product_id: id,
            productInstance: productInstance,
        });
        return result;
    }
    async updateItem(product_instance_id, updateProductInstanceDto) {
        const isExists = await this.productsService.findProductInstance({
            _id: product_instance_id,
        });
        if (!isExists) {
            throw new common_1.NotFoundException(`Product with ID ${product_instance_id} not found`);
        }
        if (Object.keys(updateProductInstanceDto).length === 0) {
            throw new common_1.UnprocessableEntityException('Invalid data');
        }
        return await this.productsService.updateProductInstance({
            id: product_instance_id,
            updateProductInstanceDto,
        });
    }
    async update(id, updateProductDto) {
        const { category_id } = updateProductDto;
        const isExists = await this.productsService.findProduct(id);
        if (!isExists) {
            throw new common_1.NotFoundException(`Product with ID ${id} not found`);
        }
        if (Object.keys(updateProductDto).length === 0) {
            throw new common_1.UnprocessableEntityException('Invalid data');
        }
        if (category_id) {
            const Categories = await Promise.all(category_id.map((id) => this.categoriesService.findCategory(id)));
            const isNotExists = Categories.some((category) => !category);
            if (isNotExists) {
                const category_id_not_found = Categories.find((category) => !category)._id.toString();
                throw new common_1.NotFoundException(`Category with ID ${category_id_not_found} not found`);
            }
        }
        else {
            updateProductDto.category_id = isExists.category_id.map((id) => id.toString());
        }
        return await this.productsService.updateProduct({ id, updateProductDto });
    }
    remove(id) {
        throw new common_1.NotImplementedException('Method not implemented.');
    }
};
exports.ProductsController = ProductsController;
__decorate([
    (0, common_1.Get)(),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'Products found' }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], ProductsController.prototype, "findAll", null);
__decorate([
    (0, common_1.Get)(':id'),
    (0, swagger_1.ApiParam)({
        name: 'id',
        type: String,
        description: 'Product ID(MongoDB ObjectId)',
    }),
    (0, swagger_1.ApiQuery)({
        name: 'product_instance_id',
        required: false,
        type: String,
        description: 'Product Instance ID(MongoDB ObjectId)',
    }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'Product found' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Product not found' }),
    (0, swagger_1.ApiResponse)({ status: 422, description: 'Invalid input' }),
    __param(0, (0, common_1.Param)('id', new paramsValidation_pipe_1.ValidateParamsPipe())),
    __param(1, (0, common_1.Query)('product_instance_id', new querysValidation_pipe_1.ValidateQueryPipe())),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String]),
    __metadata("design:returntype", Promise)
], ProductsController.prototype, "findOne", null);
__decorate([
    (0, common_1.Post)(),
    (0, swagger_1.ApiBody)({ type: create_product_dto_1.CreateProductDto, description: 'Product Data' }),
    (0, swagger_1.ApiResponse)({ status: 201, description: 'Product created' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Category not found' }),
    (0, swagger_1.ApiResponse)({ status: 422, description: 'Invalid input' }),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof create_product_dto_1.CreateProductDto !== "undefined" && create_product_dto_1.CreateProductDto) === "function" ? _c : Object]),
    __metadata("design:returntype", Promise)
], ProductsController.prototype, "create", null);
__decorate([
    (0, common_1.Post)(':id'),
    (0, swagger_1.ApiParam)({
        name: 'id',
        type: String,
        description: 'Product ID(MongoDB ObjectId)',
    }),
    (0, swagger_1.ApiBody)({
        type: create_product_dto_1.CreateProductInstanceDto,
        description: 'Product Instance Data',
    }),
    (0, swagger_1.ApiResponse)({ status: 201, description: 'Product Instance created' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Product not found' }),
    (0, swagger_1.ApiResponse)({ status: 422, description: 'Invalid input' }),
    __param(0, (0, common_1.Param)('id', new paramsValidation_pipe_1.ValidateParamsPipe())),
    __param(1, (0, common_1.Body)('productInstance')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_d = typeof create_product_dto_1.CreateProductInstanceDto !== "undefined" && create_product_dto_1.CreateProductInstanceDto) === "function" ? _d : Object]),
    __metadata("design:returntype", Promise)
], ProductsController.prototype, "createItem", null);
__decorate([
    (0, common_1.Patch)('instance/:id'),
    (0, swagger_1.ApiParam)({
        name: 'id',
        type: String,
        description: 'Product Instance ID(MongoDB ObjectId)',
    }),
    (0, swagger_1.ApiBody)({
        type: update_product_dto_1.UpdateProductInstanceDto,
        description: 'Product Instance Data',
    }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'Product updated' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Product not found' }),
    (0, swagger_1.ApiResponse)({ status: 422, description: 'Invalid input' }),
    __param(0, (0, common_1.Param)('id', new paramsValidation_pipe_1.ValidateParamsPipe())),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_e = typeof update_product_dto_1.UpdateProductInstanceDto !== "undefined" && update_product_dto_1.UpdateProductInstanceDto) === "function" ? _e : Object]),
    __metadata("design:returntype", Promise)
], ProductsController.prototype, "updateItem", null);
__decorate([
    (0, common_1.Patch)(':id'),
    (0, swagger_1.ApiParam)({
        name: 'id',
        type: String,
        description: 'Product ID(MongoDB ObjectId)',
    }),
    (0, swagger_1.ApiBody)({ type: update_product_dto_1.UpdateProductDto }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'Product updated' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Product not found' }),
    (0, swagger_1.ApiResponse)({ status: 422, description: 'Invalid input' }),
    __param(0, (0, common_1.Param)('id', new paramsValidation_pipe_1.ValidateParamsPipe())),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_f = typeof update_product_dto_1.UpdateProductDto !== "undefined" && update_product_dto_1.UpdateProductDto) === "function" ? _f : Object]),
    __metadata("design:returntype", Promise)
], ProductsController.prototype, "update", null);
__decorate([
    (0, common_1.Delete)(':id'),
    (0, swagger_1.ApiParam)({
        name: 'id',
        type: String,
        description: 'Product ID(MongoDB ObjectId)',
    }),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], ProductsController.prototype, "remove", null);
exports.ProductsController = ProductsController = __decorate([
    (0, common_1.Controller)('products'),
    (0, swagger_1.ApiTags)('Products'),
    (0, common_1.UsePipes)(new common_1.ValidationPipe({ transform: true })),
    __metadata("design:paramtypes", [typeof (_a = typeof products_service_1.ProductsService !== "undefined" && products_service_1.ProductsService) === "function" ? _a : Object, typeof (_b = typeof categories_service_1.CategoriesService !== "undefined" && categories_service_1.CategoriesService) === "function" ? _b : Object])
], ProductsController);


/***/ }),
/* 25 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateProductInstanceDto = exports.CreateProductDto = void 0;
const swagger_1 = __webpack_require__(16);
const class_validator_1 = __webpack_require__(17);
class CreateProductDto {
}
exports.CreateProductDto = CreateProductDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'category_id',
        description: 'Categories of the product',
        example: ['60f8d7f3b6f5b3001f9a1e8d'],
        type: 'array',
    }),
    (0, class_validator_1.IsNotEmpty)({ message: 'category_id must not be empty' }),
    (0, class_validator_1.IsArray)({ message: 'category_id must be an array of strings' }),
    (0, class_validator_1.Matches)(/^[0-9a-fA-F]{24}$/, { each: true, message: 'category_id is invalid' }),
    __metadata("design:type", Array)
], CreateProductDto.prototype, "category_id", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'model',
        description: 'Product Model',
        example: 'Product Model',
        type: 'string',
    }),
    (0, class_validator_1.IsNotEmpty)({ message: 'model must not be empty' }),
    (0, class_validator_1.IsString)({ message: 'model is invalid' }),
    __metadata("design:type", String)
], CreateProductDto.prototype, "model", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'description',
        description: 'Product Description',
        example: 'Product Description',
        type: 'string',
    }),
    (0, class_validator_1.IsNotEmpty)({ message: 'description must not be empty' }),
    (0, class_validator_1.IsString)({ message: 'description is invalid' }),
    __metadata("design:type", String)
], CreateProductDto.prototype, "description", void 0);
class CreateProductInstanceDto {
}
exports.CreateProductInstanceDto = CreateProductInstanceDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'product_id',
        description: 'Product ID',
        example: '60f8d7f3b6f5b3001f9a1e8d',
        type: 'string',
    }),
    (0, class_validator_1.IsNotEmpty)({ message: 'product_id must not be empty' }),
    (0, class_validator_1.IsString)({ message: 'product_id is invalid' }),
    __metadata("design:type", String)
], CreateProductInstanceDto.prototype, "product_id", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'name',
        description: 'Name of the product',
        example: 'Iphone 15 Pro Max',
        type: 'string',
    }),
    (0, class_validator_1.IsNotEmpty)({ message: 'name must not be empty' }),
    (0, class_validator_1.IsString)({ message: 'name is invalid' }),
    __metadata("design:type", String)
], CreateProductInstanceDto.prototype, "name", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'price',
        description: 'Price of the product',
        example: 100.25,
        type: 'number',
    }),
    (0, class_validator_1.IsNotEmpty)({ message: 'price must not be empty' }),
    (0, class_validator_1.IsNumber)({ maxDecimalPlaces: 2 }, { message: 'price is invalid. 2 digits max after decimal point' }),
    __metadata("design:type", Number)
], CreateProductInstanceDto.prototype, "price", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'color',
        description: 'Color of the product',
        example: 'Red',
        type: 'string',
    }),
    (0, class_validator_1.IsNotEmpty)({ message: 'color must not be empty' }),
    (0, class_validator_1.IsString)({ message: 'color is invalid' }),
    __metadata("design:type", String)
], CreateProductInstanceDto.prototype, "color", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'stock',
        description: 'Product quantity',
        example: 100,
        type: 'number',
    }),
    (0, class_validator_1.IsNotEmpty)({ message: 'stock must not be empty' }),
    (0, class_validator_1.IsNumber)({ maxDecimalPlaces: 0 }, { message: 'stock is invalid. Stock must be an integer' }),
    __metadata("design:type", Number)
], CreateProductInstanceDto.prototype, "stock", void 0);


/***/ }),
/* 26 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateProductInstanceDto = exports.UpdateProductDto = void 0;
const mapped_types_1 = __webpack_require__(27);
const create_product_dto_1 = __webpack_require__(25);
const class_validator_1 = __webpack_require__(17);
const swagger_1 = __webpack_require__(16);
class UpdateProductDto extends (0, mapped_types_1.PartialType)(create_product_dto_1.CreateProductDto) {
}
exports.UpdateProductDto = UpdateProductDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        required: false,
        name: 'category_id',
        description: 'Categories of the product',
        example: 'Product Name',
        type: [String],
    }),
    (0, class_validator_1.IsArray)({ message: 'category_id must be an array of strings' }),
    (0, class_validator_1.Matches)(/^[0-9a-fA-F]{24}$/, {
        each: true,
        message: 'category_id is invalid',
    }),
    __metadata("design:type", Array)
], UpdateProductDto.prototype, "category_id", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: false,
        name: 'model',
        description: 'Product Model',
        example: 'Product Model',
        type: 'string',
    }),
    (0, class_validator_1.IsString)({ message: 'model is invalid' }),
    __metadata("design:type", String)
], UpdateProductDto.prototype, "model", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: false,
        name: 'description',
        description: 'Product Description',
        example: 'Product Description',
        type: 'string',
    }),
    (0, class_validator_1.IsString)({ message: 'description is invalid' }),
    __metadata("design:type", String)
], UpdateProductDto.prototype, "description", void 0);
class UpdateProductInstanceDto extends (0, mapped_types_1.PartialType)(create_product_dto_1.CreateProductInstanceDto) {
}
exports.UpdateProductInstanceDto = UpdateProductInstanceDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        required: false,
        name: 'name',
        description: 'Product Name',
        example: 'Iphone 15 Pro Max',
        type: 'string',
    }),
    (0, class_validator_1.IsString)({ message: 'Product name is invalid' }),
    __metadata("design:type", String)
], UpdateProductInstanceDto.prototype, "name", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: false,
        name: 'price',
        description: 'Product Price',
        example: 100,
        type: 'number',
    }),
    (0, class_validator_1.IsNumber)({ maxDecimalPlaces: 2 }, { message: 'price is invalid. 2 digits max after decimal point' }),
    __metadata("design:type", Number)
], UpdateProductInstanceDto.prototype, "price", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: false,
        name: 'color',
        description: 'Product Color',
        example: 'Red',
        type: 'string',
    }),
    (0, class_validator_1.IsString)({ message: 'color is invalid' }),
    __metadata("design:type", String)
], UpdateProductInstanceDto.prototype, "color", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: false,
        name: 'stock',
        description: 'Product quantity',
        example: 100,
        type: 'number',
    }),
    (0, class_validator_1.IsNumber)({ maxDecimalPlaces: 0 }, { message: 'stock is invalid. Stock must be an integer' }),
    __metadata("design:type", Number)
], UpdateProductInstanceDto.prototype, "stock", void 0);


/***/ }),
/* 27 */
/***/ ((module) => {

module.exports = require("@nestjs/mapped-types");

/***/ }),
/* 28 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CategoriesService = void 0;
const common_1 = __webpack_require__(3);
const mongodb_1 = __webpack_require__(10);
const database_service_1 = __webpack_require__(11);
const categories_schemas_1 = __webpack_require__(29);
let CategoriesService = class CategoriesService {
    constructor(databaseService) {
        this.databaseService = databaseService;
    }
    async findAllCategories() {
        return await this.databaseService.categories.find().toArray();
    }
    async findCategory(id) {
        return await this.databaseService.categories.findOne({
            _id: new mongodb_1.ObjectId(id),
        });
    }
    async findNameOfCategory(name) {
        return await this.databaseService.categories.findOne({ name });
    }
    async insertCategory(createCategoryDto) {
        const { parents } = createCategoryDto;
        return await this.databaseService.categories.insertOne(new categories_schemas_1.Category({
            ...createCategoryDto,
            parents: parents ? new mongodb_1.ObjectId(parents) : null,
        }));
    }
    async updateCategory({ id, updateCategoryDto, }) {
        const { parents } = updateCategoryDto;
        const parents_id = parents ? new mongodb_1.ObjectId(parents) : null;
        return await this.databaseService.categories.findOneAndUpdate({ _id: new mongodb_1.ObjectId(id) }, {
            $set: {
                ...updateCategoryDto,
                parents: parents_id,
            },
        }, { returnDocument: 'after' });
    }
    async deleteCategory(id) {
        return await this.databaseService.categories.findOneAndDelete({
            _id: new mongodb_1.ObjectId(id),
        });
    }
};
exports.CategoriesService = CategoriesService;
exports.CategoriesService = CategoriesService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof database_service_1.DatabaseService !== "undefined" && database_service_1.DatabaseService) === "function" ? _a : Object])
], CategoriesService);


/***/ }),
/* 29 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Category = void 0;
const mongodb_1 = __webpack_require__(10);
class Category {
    constructor(category) {
        this._id = category._id || new mongodb_1.ObjectId();
        this.name = category.name;
        this.description = category.description;
        this.created_at = category.created_at || new Date();
        this.updated_at = category.updated_at || new Date();
        this.parents = category.parents;
    }
}
exports.Category = Category;


/***/ }),
/* 30 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ValidateParamsPipe = void 0;
const common_1 = __webpack_require__(3);
const ObjectIdRegex = /^[0-9a-fA-F]{24}$/;
let ValidateParamsPipe = class ValidateParamsPipe {
    transform(value, metadata) {
        if (metadata.type === 'param') {
            if (metadata.data === 'id') {
                if (!value.match(ObjectIdRegex)) {
                    throw new common_1.UnprocessableEntityException('Invalid Param ID. ID must be a valid MongoDB ObjectId');
                }
            }
        }
        return value;
    }
};
exports.ValidateParamsPipe = ValidateParamsPipe;
exports.ValidateParamsPipe = ValidateParamsPipe = __decorate([
    (0, common_1.Injectable)()
], ValidateParamsPipe);


/***/ }),
/* 31 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ValidateQueryPipe = void 0;
const common_1 = __webpack_require__(3);
const ObjectIdRegex = /^[0-9a-fA-F]{24}$/;
let ValidateQueryPipe = class ValidateQueryPipe {
    transform(value, metadata) {
        if (metadata.type === 'query') {
            if (!value) {
                return value;
            }
            if (!ObjectIdRegex.test(value.id)) {
                throw new common_1.UnprocessableEntityException('Invalid Query ID. ID must be a valid MongoDB ObjectId');
            }
            return value;
        }
    }
};
exports.ValidateQueryPipe = ValidateQueryPipe;
exports.ValidateQueryPipe = ValidateQueryPipe = __decorate([
    (0, common_1.Injectable)()
], ValidateQueryPipe);


/***/ }),
/* 32 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.GuardModule = void 0;
const common_1 = __webpack_require__(3);
const config_1 = __webpack_require__(12);
const jwt_1 = __webpack_require__(14);
const auth_guard_1 = __webpack_require__(33);
let GuardModule = class GuardModule {
};
exports.GuardModule = GuardModule;
exports.GuardModule = GuardModule = __decorate([
    (0, common_1.Module)({
        imports: [jwt_1.JwtModule, config_1.ConfigModule.forRoot({
                envFilePath: ['.env'],
            })],
        providers: [auth_guard_1.AuthGuard],
    })
], GuardModule);


/***/ }),
/* 33 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthGuard = void 0;
const common_1 = __webpack_require__(3);
const config_1 = __webpack_require__(12);
const jwt_1 = __webpack_require__(14);
let AuthGuard = class AuthGuard {
    constructor(configService, jwtService) {
        this.configService = configService;
        this.jwtService = jwtService;
    }
    canActivate(context) {
        const request = context.switchToHttp().getRequest();
        return this.validateRequest(request);
    }
    validateRequest(request) {
        const authorization = request.headers['authorization'];
        if (!authorization) {
            return false;
        }
        const [bearer, token] = authorization.split(' ');
        if (bearer !== 'Bearer' || !token) {
            return false;
        }
        try {
            this.jwtService.verify(token, {
                secret: this.configService.get('ACCESS_TOKEN_SECRET'),
            });
            return true;
        }
        catch {
            return false;
        }
    }
};
exports.AuthGuard = AuthGuard;
exports.AuthGuard = AuthGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object, typeof (_b = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _b : Object])
], AuthGuard);


/***/ }),
/* 34 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CategoriesController = void 0;
const common_1 = __webpack_require__(3);
const categories_service_1 = __webpack_require__(28);
const create_category_dto_1 = __webpack_require__(35);
const update_category_dto_1 = __webpack_require__(36);
const paramsValidation_pipe_1 = __webpack_require__(30);
const swagger_1 = __webpack_require__(16);
let CategoriesController = class CategoriesController {
    constructor(categoriesService) {
        this.categoriesService = categoriesService;
    }
    async findAllCategories() {
        return await this.categoriesService.findAllCategories();
    }
    async findCategory(id) {
        const result = await this.categoriesService.findCategory(id);
        if (!result) {
            throw new common_1.NotFoundException('Category not found');
        }
        return result;
    }
    async insertCategory(createCategoryDto) {
        const { name } = createCategoryDto;
        const isExists = await this.categoriesService.findNameOfCategory(name);
        if (isExists) {
            throw new common_1.UnprocessableEntityException('Name already exists');
        }
        return await this.categoriesService.insertCategory(createCategoryDto);
    }
    async updateCategory(id, updateCategoryDto) {
        const { parents } = updateCategoryDto;
        const isExists = await this.categoriesService.findCategory(id);
        if (!isExists) {
            throw new common_1.NotFoundException('Category not found');
        }
        if (Object.keys(updateCategoryDto).length === 0) {
            throw new common_1.UnprocessableEntityException('Invalid data');
        }
        if (!parents) {
            if (parents === '') {
                updateCategoryDto.parents = null;
            }
            else {
                updateCategoryDto.parents = isExists.parents
                    ? isExists.parents.toString()
                    : null;
            }
        }
        return await this.categoriesService.updateCategory({
            id,
            updateCategoryDto,
        });
    }
    async deleteCategory(id) {
        const isExists = await this.categoriesService.findCategory(id);
        if (!isExists) {
            throw new common_1.NotFoundException('Category not found');
        }
        return await this.categoriesService.deleteCategory(id);
    }
};
exports.CategoriesController = CategoriesController;
__decorate([
    (0, common_1.Get)(),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'Categories found' }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], CategoriesController.prototype, "findAllCategories", null);
__decorate([
    (0, common_1.Get)(':id'),
    (0, swagger_1.ApiParam)({
        name: 'id',
        type: String,
        description: 'Category ID(MongoDB ObjectId)',
    }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'Category found' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Category not found' }),
    __param(0, (0, common_1.Param)('id', new paramsValidation_pipe_1.ValidateParamsPipe())),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", Promise)
], CategoriesController.prototype, "findCategory", null);
__decorate([
    (0, common_1.Post)(),
    (0, swagger_1.ApiBody)({ type: create_category_dto_1.CreateCategoryDto, description: 'Category Data' }),
    (0, swagger_1.ApiResponse)({ status: 201, description: 'Category created' }),
    (0, swagger_1.ApiResponse)({ status: 422, description: 'Invalid input' }),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof create_category_dto_1.CreateCategoryDto !== "undefined" && create_category_dto_1.CreateCategoryDto) === "function" ? _b : Object]),
    __metadata("design:returntype", Promise)
], CategoriesController.prototype, "insertCategory", null);
__decorate([
    (0, common_1.Patch)(':id'),
    (0, swagger_1.ApiParam)({
        name: 'id',
        type: String,
        description: 'Category ID(MongoDB ObjectId)',
    }),
    (0, swagger_1.ApiBody)({ type: update_category_dto_1.UpdateCategoryDto, description: 'Category Data' }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'Category updated' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Category not found' }),
    (0, swagger_1.ApiResponse)({ status: 422, description: 'Invalid input' }),
    __param(0, (0, common_1.Param)('id', new paramsValidation_pipe_1.ValidateParamsPipe())),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_c = typeof update_category_dto_1.UpdateCategoryDto !== "undefined" && update_category_dto_1.UpdateCategoryDto) === "function" ? _c : Object]),
    __metadata("design:returntype", Promise)
], CategoriesController.prototype, "updateCategory", null);
__decorate([
    (0, common_1.Delete)(':id'),
    (0, swagger_1.ApiParam)({
        name: 'id',
        type: String,
        description: 'Category ID(MongoDB ObjectId)',
    }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'Category deleted' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Category not found' }),
    (0, swagger_1.ApiResponse)({ status: 422, description: 'Invalid input' }),
    __param(0, (0, common_1.Param)('id', new paramsValidation_pipe_1.ValidateParamsPipe())),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", Promise)
], CategoriesController.prototype, "deleteCategory", null);
exports.CategoriesController = CategoriesController = __decorate([
    (0, common_1.Controller)('categories'),
    (0, swagger_1.ApiTags)('Categories'),
    (0, common_1.UsePipes)(new common_1.ValidationPipe({ transform: true })),
    __metadata("design:paramtypes", [typeof (_a = typeof categories_service_1.CategoriesService !== "undefined" && categories_service_1.CategoriesService) === "function" ? _a : Object])
], CategoriesController);


/***/ }),
/* 35 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateCategoryDto = void 0;
const swagger_1 = __webpack_require__(16);
const class_validator_1 = __webpack_require__(17);
class CreateCategoryDto {
}
exports.CreateCategoryDto = CreateCategoryDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'name',
        description: 'Name of the category',
        example: 'Category Name',
        type: 'string',
    }),
    (0, class_validator_1.IsNotEmpty)({ message: 'name must not be empty' }),
    (0, class_validator_1.IsString)({ message: 'name is invalid' }),
    __metadata("design:type", String)
], CreateCategoryDto.prototype, "name", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        name: 'description',
        description: 'Description of the category',
        example: 'Category Description',
        type: 'string',
    }),
    (0, class_validator_1.IsNotEmpty)({ message: 'description must not be empty' }),
    (0, class_validator_1.IsString)({ message: 'description is invalid' }),
    __metadata("design:type", String)
], CreateCategoryDto.prototype, "description", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: false,
        name: 'parents',
        description: 'Parents of the category',
        example: 'Parents',
        type: 'string',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)({ message: 'parents_id is invalid' }),
    __metadata("design:type", String)
], CreateCategoryDto.prototype, "parents", void 0);


/***/ }),
/* 36 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateCategoryDto = void 0;
const mapped_types_1 = __webpack_require__(27);
const create_category_dto_1 = __webpack_require__(35);
const class_validator_1 = __webpack_require__(17);
const swagger_1 = __webpack_require__(16);
class UpdateCategoryDto extends (0, mapped_types_1.PartialType)(create_category_dto_1.CreateCategoryDto) {
}
exports.UpdateCategoryDto = UpdateCategoryDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        required: false,
        name: 'name',
        description: 'Name of the category',
        example: 'Category Name',
        type: 'string',
    }),
    (0, class_validator_1.IsString)({ message: 'name is invalid' }),
    __metadata("design:type", String)
], UpdateCategoryDto.prototype, "name", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: false,
        name: 'description',
        description: 'Description of the category',
        example: 'Category Description',
        type: 'string',
    }),
    (0, class_validator_1.IsString)({ message: 'description is invalid' }),
    __metadata("design:type", String)
], UpdateCategoryDto.prototype, "description", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: false,
        name: 'parents',
        description: 'Parents of the category',
        example: 'Parents',
        type: 'string',
    }),
    (0, class_validator_1.IsString)({ message: 'parents is invalid' }),
    __metadata("design:type", String)
], UpdateCategoryDto.prototype, "parents", void 0);


/***/ }),
/* 37 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.OrdersModule = void 0;
const common_1 = __webpack_require__(3);
const orders_service_1 = __webpack_require__(38);
const orders_controller_1 = __webpack_require__(40);
const guard_module_1 = __webpack_require__(32);
const jwt_1 = __webpack_require__(14);
const config_1 = __webpack_require__(12);
const database_module_1 = __webpack_require__(19);
const users_module_1 = __webpack_require__(6);
const products_module_1 = __webpack_require__(21);
let OrdersModule = class OrdersModule {
};
exports.OrdersModule = OrdersModule;
exports.OrdersModule = OrdersModule = __decorate([
    (0, common_1.Module)({
        imports: [
            guard_module_1.GuardModule,
            jwt_1.JwtModule,
            config_1.ConfigModule.forRoot({
                envFilePath: ['.env'],
            }),
            database_module_1.DatabaseModule,
            users_module_1.UsersModule,
            products_module_1.ProductsModule,
        ],
        controllers: [orders_controller_1.OrdersController],
        providers: [orders_service_1.OrdersService],
    })
], OrdersModule);


/***/ }),
/* 38 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.OrdersService = void 0;
const common_1 = __webpack_require__(3);
const mongodb_1 = __webpack_require__(10);
const database_service_1 = __webpack_require__(11);
const orders_schemas_1 = __webpack_require__(39);
let OrdersService = class OrdersService {
    constructor(databaseService) {
        this.databaseService = databaseService;
    }
    async getOrders() {
        return await this.databaseService.orders.find().toArray();
    }
    async getOrder(id) {
        return await this.databaseService.orders.findOne({ _id: new mongodb_1.ObjectId(id) });
    }
    async createOrder(order) {
        return await this.databaseService.orders.insertOne(new orders_schemas_1.Order({
            user_id: new mongodb_1.ObjectId(order.user_id),
        }));
    }
    async getOrderItem(id) {
        return await this.databaseService.order_items.findOne({
            _id: new mongodb_1.ObjectId(id),
        });
    }
    async getOrderItems(order_id) {
        return await this.databaseService.order_items
            .find({ order_id: new mongodb_1.ObjectId(order_id) })
            .toArray();
    }
    async getOrdersOfUser(user_id) {
        return await this.databaseService.orders
            .find({ user_id: new mongodb_1.ObjectId(user_id) })
            .toArray();
    }
    async createOrderItems(orderItems) {
        return await this.databaseService.order_items.insertMany(orderItems.map((orderItem) => new orders_schemas_1.OrderItem({
            order_id: new mongodb_1.ObjectId(orderItem.order_id),
            product_id: new mongodb_1.ObjectId(orderItem.product_id),
            quantity: orderItem.quantity,
        })));
    }
    async updateOrder(order) {
        return await this.databaseService.orders.findOneAndUpdate({ _id: new mongodb_1.ObjectId(order._id) }, {
            $set: {
                user_id: new mongodb_1.ObjectId(order.user_id),
            },
        });
    }
    async updateOrderItem(orderItem) {
        return await this.databaseService.order_items.findOneAndUpdate({ _id: new mongodb_1.ObjectId(orderItem._id) }, {
            $set: {
                order_id: new mongodb_1.ObjectId(orderItem.order_id),
                product_id: new mongodb_1.ObjectId(orderItem.product_id),
                quantity: orderItem.quantity,
            },
        }, { returnDocument: 'after' });
    }
};
exports.OrdersService = OrdersService;
exports.OrdersService = OrdersService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof database_service_1.DatabaseService !== "undefined" && database_service_1.DatabaseService) === "function" ? _a : Object])
], OrdersService);


/***/ }),
/* 39 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.OrderItem = exports.Order = void 0;
const mongodb_1 = __webpack_require__(10);
class Order {
    constructor(order) {
        this._id = order._id || new mongodb_1.ObjectId();
        this.user_id = order.user_id;
        this.created_at = order.created_at || new Date();
        this.updated_at = order.updated_at || new Date();
    }
}
exports.Order = Order;
class OrderItem {
    constructor(orderItem) {
        this._id = orderItem._id || new mongodb_1.ObjectId();
        this.order_id = orderItem.order_id;
        this.product_id = orderItem.product_id;
        this.quantity = orderItem.quantity;
        this.created_at = orderItem.create_at || new Date();
        this.updated_at = orderItem.updated_at || new Date();
    }
}
exports.OrderItem = OrderItem;


/***/ }),
/* 40 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.OrdersController = void 0;
const common_1 = __webpack_require__(3);
const orders_service_1 = __webpack_require__(38);
const swagger_1 = __webpack_require__(16);
const paramsValidation_pipe_1 = __webpack_require__(30);
const querysValidation_pipe_1 = __webpack_require__(31);
const create_order_dto_1 = __webpack_require__(41);
const users_service_1 = __webpack_require__(8);
const products_service_1 = __webpack_require__(22);
let OrdersController = class OrdersController {
    constructor(ordersService, usersService, productsService) {
        this.ordersService = ordersService;
        this.usersService = usersService;
        this.productsService = productsService;
    }
    async findAll(user_id) {
        if (user_id) {
            const isExists = await this.usersService.checkUserExists(user_id);
            if (!isExists) {
                throw new common_1.NotFoundException('User not found');
            }
            return await this.ordersService.getOrdersOfUser(user_id);
        }
        return await this.ordersService.getOrders();
    }
    async findOne(id, product_item_id) {
        const order = await this.ordersService.getOrder(id);
        if (!order) {
            throw new common_1.NotFoundException('Order not found');
        }
        if (!product_item_id) {
            const product_items = await this.ordersService.getOrderItems(id);
            return { ...order, product_items };
        }
        const product_item = await this.ordersService.getOrderItem(product_item_id);
        if (!product_item) {
            throw new common_1.NotFoundException('Order Item not found');
        }
        return { ...order, product_item };
    }
    async createOrder(createOrderDto) {
        const { user_id } = createOrderDto;
        const isExists = await this.usersService.checkUserExists(user_id);
        if (!isExists) {
            throw new common_1.NotFoundException('User not found');
        }
        return await this.ordersService.createOrder(createOrderDto);
    }
    async createOrderItem(createOrderItemDto) {
        const orders_id = createOrderItemDto.map((orderItem) => orderItem.order_id);
        const orders = await Promise.all(orders_id.map((id) => this.ordersService.getOrder(id)));
        const isNotExists = orders.some((order) => !order);
        if (isNotExists) {
            const order_id_not_exist = orders.find((order) => !order)._id.toString();
            throw new common_1.NotFoundException(`Order with ID ${order_id_not_exist} not found`);
        }
        const products_id = createOrderItemDto.map((orderItem) => orderItem.product_id);
        const products = await Promise.all(products_id.map((id) => this.productsService.findProduct(id)));
        const isNotExistsProduct = products.some((product) => !product);
        if (isNotExistsProduct) {
            const product_id_not_exist = products.find((product) => !product)._id;
            throw new common_1.NotFoundException(`Product with ID ${product_id_not_exist} not found`);
        }
        return await this.ordersService.createOrderItems(createOrderItemDto);
    }
};
exports.OrdersController = OrdersController;
__decorate([
    (0, common_1.Get)(),
    (0, swagger_1.ApiQuery)({
        required: false,
        name: 'user_id',
        example: '60f1c9e6e2e4e6f9b6f0d5d6',
        description: 'User ID of the user who made the order',
    }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'Get orders successfully' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'User not found' }),
    (0, swagger_1.ApiResponse)({ status: 422, description: 'Invalid input' }),
    __param(0, (0, common_1.Query)('user_id', new querysValidation_pipe_1.ValidateQueryPipe())),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", Promise)
], OrdersController.prototype, "findAll", null);
__decorate([
    (0, common_1.Get)(':id'),
    (0, swagger_1.ApiParam)({
        required: true,
        name: 'id',
        example: '60f1c9e6e2e4e6f9b6f0d5d6',
        description: 'Order ID',
        type: String,
    }),
    (0, swagger_1.ApiQuery)({
        required: false,
        name: 'product_item_id',
        example: '60f1c9e6e2e4e6f9b6f0d5d6',
        description: 'Order Item ID',
        type: String,
    }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'Get order successfully' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Order or OrderItem not found' }),
    (0, swagger_1.ApiResponse)({ status: 422, description: 'Invalid input' }),
    __param(0, (0, common_1.Param)('id', new paramsValidation_pipe_1.ValidateParamsPipe())),
    __param(1, (0, common_1.Query)('product_item_id', new querysValidation_pipe_1.ValidateQueryPipe())),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String]),
    __metadata("design:returntype", Promise)
], OrdersController.prototype, "findOne", null);
__decorate([
    (0, common_1.Post)(),
    (0, swagger_1.ApiBody)({
        type: create_order_dto_1.CreateOrderDto,
        description: 'Order Data',
        required: true,
    }),
    (0, swagger_1.ApiResponse)({ status: 201, description: 'Order created' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'User not found' }),
    (0, swagger_1.ApiResponse)({ status: 422, description: 'Invalid input' }),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_d = typeof create_order_dto_1.CreateOrderDto !== "undefined" && create_order_dto_1.CreateOrderDto) === "function" ? _d : Object]),
    __metadata("design:returntype", Promise)
], OrdersController.prototype, "createOrder", null);
__decorate([
    (0, common_1.Post)('items'),
    (0, swagger_1.ApiBody)({
        required: true,
        type: [create_order_dto_1.CreateOrderItemDto],
        description: 'Order Item Data',
    }),
    (0, swagger_1.ApiResponse)({ status: 201, description: 'Order Item created' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Order/Product not found' }),
    (0, swagger_1.ApiResponse)({ status: 422, description: 'Invalid input' }),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Array]),
    __metadata("design:returntype", Promise)
], OrdersController.prototype, "createOrderItem", null);
exports.OrdersController = OrdersController = __decorate([
    (0, common_1.Controller)('orders'),
    (0, swagger_1.ApiTags)('Orders'),
    (0, common_1.UsePipes)(new common_1.ValidationPipe()),
    __metadata("design:paramtypes", [typeof (_a = typeof orders_service_1.OrdersService !== "undefined" && orders_service_1.OrdersService) === "function" ? _a : Object, typeof (_b = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _b : Object, typeof (_c = typeof products_service_1.ProductsService !== "undefined" && products_service_1.ProductsService) === "function" ? _c : Object])
], OrdersController);


/***/ }),
/* 41 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateOrderItemDto = exports.CreateOrderDto = void 0;
const swagger_1 = __webpack_require__(16);
const class_validator_1 = __webpack_require__(17);
class CreateOrderDto {
}
exports.CreateOrderDto = CreateOrderDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        example: '60f1c9e6e2e4e6f9b6f0d5d6',
        description: 'User ID of the user who made the order',
        format: 'MongoDB ObjectId',
        type: String,
    }),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Matches)(/^[0-9a-fA-F]{24}$/, {
        message: 'Invalid user_id, user_id must be a MongoDB ObjectId',
    }),
    __metadata("design:type", String)
], CreateOrderDto.prototype, "user_id", void 0);
class CreateOrderItemDto {
}
exports.CreateOrderItemDto = CreateOrderItemDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        example: '60f1c9e6e2e4e6f9b6f0d5d6',
        description: 'Order ID of the order to which the item belongs',
        format: 'MongoDB ObjectId',
        type: String,
    }),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Matches)(/^[0-9a-fA-F]{24}$/, {
        message: 'Invalid order_id, order_id must be a MongoDB ObjectId',
    }),
    __metadata("design:type", String)
], CreateOrderItemDto.prototype, "order_id", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        example: '60f1c9e6e2e4e6f9b6f0d5d6',
        description: 'Product ID of the product in the order',
        format: 'MongoDB ObjectId',
        type: String,
    }),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Matches)(/^[0-9a-fA-F]{24}$/, {
        message: 'Invalid product_id, product_id must be a MongoDB ObjectId',
    }),
    __metadata("design:type", String)
], CreateOrderItemDto.prototype, "product_id", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        required: true,
        example: 5,
        description: 'Quantity of the product in the order',
        type: Number,
    }),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsNumber)({ maxDecimalPlaces: 0 }, { message: 'Invalid quantity, quantity must be an integer' }),
    __metadata("design:type", Number)
], CreateOrderItemDto.prototype, "quantity", void 0);


/***/ }),
/* 42 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HttpExceptionFilter = void 0;
const common_1 = __webpack_require__(3);
let HttpExceptionFilter = class HttpExceptionFilter {
    catch(exception, host) {
        if (exception instanceof common_1.HttpException) {
            const cxt = host.switchToHttp();
            const msg = exception.message;
            const res = exception.getResponse();
            const status = exception.getStatus();
            const response = cxt.getResponse();
            console.error(exception);
            response.status(status).json({
                statusCode: status,
                message: { msg, res },
            });
        }
        else {
            throw exception;
        }
    }
};
exports.HttpExceptionFilter = HttpExceptionFilter;
exports.HttpExceptionFilter = HttpExceptionFilter = __decorate([
    (0, common_1.Catch)()
], HttpExceptionFilter);


/***/ })
/******/ 	]);
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it uses a non-standard name for the exports (exports).
(() => {
var exports = __webpack_exports__;

Object.defineProperty(exports, "__esModule", ({ value: true }));
const core_1 = __webpack_require__(1);
const app_module_1 = __webpack_require__(2);
const swagger_1 = __webpack_require__(16);
const http_exception_filter_filter_1 = __webpack_require__(42);
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    app.useGlobalFilters(new http_exception_filter_filter_1.HttpExceptionFilter());
    const config = new swagger_1.DocumentBuilder()
        .setTitle('Shopping Cart API')
        .setDescription('Shopping Cart API list, built with NestJS')
        .setVersion('1.0')
        .build();
    const documentFactory = () => swagger_1.SwaggerModule.createDocument(app, config);
    swagger_1.SwaggerModule.setup('api', app, documentFactory);
    await app.listen(3000);
    console.log(`Application is running on: ${await app.getUrl()}`);
}
bootstrap();

})();

/******/ })()
;