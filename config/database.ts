import mongoose from "mongoose";

const { MONGO_URI } = process.env;

exports.connect = () => {
  mongoose
    .connect(MONGO_URI??"", )
    .then(() => {
      console.log("Successfully connected to database");
    })
    .catch((error: any) => {
      console.log("database connection failed. exiting now...");
      console.error(error);
      process.exit(1);
    });
};
