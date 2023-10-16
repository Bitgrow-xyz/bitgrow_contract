// SPDX-License-Identifier: MIT
pragma solidity ^0.8.14;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract BitGrow is Ownable, ReentrancyGuard {
    using ECDSA for bytes32;
    using SafeMath for uint256;

    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    struct Claim {
        address account;
        uint256[] orderIds;
        bytes sign;
    }

    bytes32 constant EIP712DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 constant CLAIM_TYPEHASH = keccak256(
        "Claim(address account,uint256[] orderIds)"
    );

    bytes32 private DOMAIN_SEPARATOR;
    address public signer; //官方签名地址
    event finishOrder(address indexed acount, uint256 reward); //完成订单事件

    struct OrderInfo {
        ProjectInfo projectInfo; //项目信息
        string orderName; //订单名称
        string orderRemark; //订单备注
        string copywriting; //推广文案内容
        uint256 orderAmount; //订单报酬（eth计价单位）
        address koladdress; //如需指定kol，请输入kol地址，否则传0地址即可
        address officialaddress; //项目方自身地址
        address acceptUseraddress; //接受任务用户地址
        OrderState orderState; //订单状态
    }

    struct ProjectInfo {
        string projectName; //项目名称
        string projectLogo; //项目Logo
        string projectX; //项目twitter
        string officialWebsite; //项目官网
    }

    enum OrderState {
        PendingCollect, //待领取
        InProgress, //进行中
        Completed, //已完成
        Canceled //已取消
    }

    uint256 public orderTotalAmount; //平台总订单数量
    mapping(uint256 => OrderInfo) public orderInfos; //平台订单详情信息
    mapping(address => uint256[]) public myOrderIndex; //我发布的订单总序号

    modifier callerIsUser() {
        require(tx.origin == msg.sender, "Must from real wallet address");
        _;
    }

    modifier callerIsPlatform(address platform) {
        require(platform == msg.sender, "Must from platform address");
        _;
    }

    constructor ()  {
        DOMAIN_SEPARATOR = hash(EIP712Domain({
        name : "BitGrow",
        version : '1.0.0',
        chainId : block.chainid,
        verifyingContract : address(this)
        }));
        signer = msg.sender;
    }

    receive() payable external {}

    //创建订单
    function createOrder(OrderInfo memory OrderInfo_) public payable callerIsUser
    {
        OrderInfo_.orderState = OrderState.PendingCollect;
        OrderInfo_.officialaddress = msg.sender;
        require(msg.value >= OrderInfo_.orderAmount, "Ether is not enough");
        orderTotalAmount++;
        orderInfos[orderTotalAmount] = OrderInfo_;
        myOrderIndex[msg.sender].push(orderTotalAmount);
    }

    //接收订单
    function acceptOrder(uint256 orderIndex) public callerIsUser
    {
        require(orderInfos[orderIndex].orderState == OrderState.PendingCollect, "State Error.");
        orderInfos[orderIndex].orderState = OrderState.InProgress;
        orderInfos[orderIndex].acceptUseraddress = msg.sender;
    }

    //取消订单
    function cancelOrder(uint256 orderIndex) public callerIsUser
    {
        require(orderInfos[orderIndex].orderState == OrderState.PendingCollect, "State Error.");
        require(msg.sender == orderInfos[orderIndex].officialaddress, "The project party needs to be able to modify it themselves.");
        orderInfos[orderIndex].orderState = OrderState.Canceled;
        (bool success,) = address(orderInfos[orderIndex].officialaddress).call{value : orderInfos[orderIndex].orderAmount}("");
        require(success, "Transfer failed.");
    }

    //取消订单并领取佣金
    function endOrder(Claim memory claim) public callerIsUser {
        bytes32 digest = keccak256(abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                hash(claim)
            ));
        require(digest.recover(claim.sign) == signer, "Error: sign invalid");
        for (uint256 i = 0; i < claim.orderIds.length; i++) {
            uint256 orderIndex=claim.orderIds[i];
            if (orderInfos[orderIndex].orderState == OrderState.InProgress){
                (bool success,) = address(orderInfos[orderIndex].acceptUseraddress).call{value : orderInfos[orderIndex].orderAmount}("");
                require(success, "Transfer failed.");
                emit finishOrder(orderInfos[orderIndex].acceptUseraddress, orderInfos[orderIndex].orderAmount);
                orderInfos[orderIndex].orderState = OrderState.Completed;
            }
        }
    }

    //获取我创建的订单列表
    function getMyOrderIndex() public view returns (uint256[] memory) {
        return myOrderIndex[msg.sender];
    }


    function hash(EIP712Domain memory eip712Domain) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712DOMAIN_TYPEHASH,
                keccak256(bytes(eip712Domain.name)),
                keccak256(bytes(eip712Domain.version)),
                eip712Domain.chainId,
                eip712Domain.verifyingContract
            ));
    }

    function hash(Claim memory claim) public pure returns (bytes32) {
        return keccak256(abi.encode(
                CLAIM_TYPEHASH,
                claim.account,
                claim.orderIds
            ));
    }

    //变更官方签名钱包
    function changeSigner(address newSigner) public onlyOwner {
        signer = newSigner;
    }
}

