const Report = artifacts.require("Report");

module.exports = function(deployer) {
  deployer.deploy(Report);
};
