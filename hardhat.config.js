require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config(); // Add this line

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.28",
  networks: {
    // Add this networks block
    amoy: {
      url: process.env.POLYGON_AMOY_RPC_URL || "",
      accounts:
        process.env.PRIVATE_KEY !== undefined ? [process.env.PRIVATE_KEY] : [],
    },
  },
};