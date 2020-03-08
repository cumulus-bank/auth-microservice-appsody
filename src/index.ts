import { Router } from "express";
import * as express from "express";
import * as passportJWT from "passport-jwt";
import * as jwt from "jsonwebtoken";
import * as passwordhash from "password-hash";
let mariadb = require("mariadb");
import "reflect-metadata";
class IndexController {
  public jwtOptions: any = {};
  public ExtractJwt = passportJWT.ExtractJwt;
  public JwtStrategy = passportJWT.ExtractJwt;
  public express: express.Application;
  public connectionString: any;
  public newdata: any = [];
  public pool: any;
  public router: Router;
  constructor() {
    this.jwtOptions.jwtFromRequest = this.ExtractJwt.fromAuthHeaderAsBearerToken();
    this.jwtOptions.secretOrKey = process.env.SECRET;
    this.connectionString = {
      host: process.env.HOST,
      user: process.env.UID,
      password: process.env.PASSWORD,
      database: process.env.DATABASE,
      connectionLimit: 5,
      port: process.env.PORT
    };
    this.pool = mariadb.createPool(this.connectionString);
    console.log(this.connectionString);

    this.router = Router();
    this.routes();
  }
  private routes() {
    this.router.get("/healthz", (_, res) => {
      res.status(200).send({success:"ok"});
    });
    this.router.get("/test", (_, res) => {
      res.status(200).send({success:"test"});
    });
    this.router.post("/login", (req, res) => {
      // res.status(200).send({success:"test"});
      this.pool
      .getConnection()
      .then(conn => {
        conn
          .query(
            "SELECT * FROM SAMPLE.UserData WHERE Email=?",
            [
              req.body.email
            ]
          )
          .then(data => {
            if (!data) {
              conn.end();
              res
                .status(401)
                .json({ message: "Please signup, no email exists" });
            } else if (
              passwordhash.verify(req.body.password, data[0]['Password'])
            ) {
              conn.end();
              console.log(process.env.SECRET);
              data = { data: data };
              res.json({
                sucessful: true,
                token: jwt.sign(data, process.env.SECRET)
              });
            } else {
              conn.end();
              res
                .status(401)
                .json({ message: "Password/Email did not match" });
            }
          })
          .catch(err => {
            conn.end();
            if (err) {
              res.status(404).json({ err });
              console.log(err);
            }
          });
      })
      .catch(err => {
        if (err) {
          res.status(404).json({ err });
          console.log(err);
        }
      });
    });

    this.router.post("/createUser", (req, res) => {
      this.newdata = [];
      this.pool
        .getConnection()
        .then(conn => {
          conn
            .query("insert into SAMPLE.UserData (LastName, FirstName, Email, Password, Age, Mobile) VALUES (?, ?, ?, ?, ?, ?)", [
              req.body.lastName,
              req.body.firstName,
              req.body.email,
              passwordhash.generate(req.body.password),
              req.body.age,
              req.body.mobile
            ])
            .then(data => {
              conn.end();
              res.json({
                message: "sucessful"
              });
            })
            .catch(err => {
              conn.end();
              if (err) {
                res.status(404).json({ err });
              }
            });
        })
        .catch(err => {
          if (err) {
            res.status(404).json({ err });
          }
        });
    });
  }

}
export default new IndexController().router;