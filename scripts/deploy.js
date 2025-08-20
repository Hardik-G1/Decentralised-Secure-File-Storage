const hre = require("hardhat");

async function main() {
  console.log("Getting the FileRegistry contract factory...");
  const FileRegistry = await hre.ethers.getContractFactory("FileRegistry");

  console.log("Deploying FileRegistry contract... Please wait.");
  const fileRegistry = await FileRegistry.deploy();
  console.log(`\n🎉 FileRegistry contract deployed successfully!`);
  console.log(`Contract Address: ${fileRegistry.target}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});