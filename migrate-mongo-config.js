// In this file you can configure migrate-mongo
// Load the same .env the server uses so `migrate-mongo` connects to the same DB.
// dotenv does not override variables already set in the environment (e.g. inside
// the Docker container), so this is safe in every environment.
require("dotenv").config();

const mongoHost = process.env.MONGO_HOST;
const mongoUsername = process.env.MONGO_USERNAME;
const mongoPassword = process.env.MONGO_PASSWORD;

const config = {
  mongodb: {
    // TODO Change (or review) the url to your MongoDB:
    url: `mongodb://${mongoUsername}:${mongoPassword}@${mongoHost}`,

    // TODO Change this to your database name:
    databaseName: "origami",

    options: {
      // useNewUrlParser / useUnifiedTopology were removed in MongoDB driver v4+
      // and are rejected as errors by the driver migrate-mongo now uses.
      //   connectTimeoutMS: 3600000, // increase connection timeout to 1 hour
      //   socketTimeoutMS: 3600000, // increase socket timeout to 1 hour
    },
  },

  // The migrations dir, can be an relative or absolute path. Only edit this when really necessary.
  migrationsDir: "migrations",

  // The mongodb collection where the applied changes are stored. Only edit this when really necessary.
  changelogCollectionName: "changelog",

  // The file extension to create migrations and search for in migration dir
  migrationFileExtension: ".js",
};

// Return the config as a promise
module.exports = config;
