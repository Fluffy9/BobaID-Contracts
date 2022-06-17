import "./TuringHelper.sol";

contract oAuthGithub {
    // All users who have been authenticated with their account ID
    mapping(uint256 => address) public authenticatedUsers;
    // Users who are halfway through authentication
    mapping(string => address) public unauthenticated;
    // The timestamp of when a user was set on the unauthenticated list
    // After enough time, we will allow an entry to be overwritten to prevent squatting
    mapping(string => uint256) public unauthenticatedTimestamp;
    string public url;
    address public turingHelperAddress;
    TuringHelper public turing;
    address owner;

    event Proved(address indexed _user, uint256 indexed _id);
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    constructor(string memory _url) {
        // The turing URL
        url = _url;
        // The owner who will set the turing helper address
        owner = msg.sender;
    }

    // set the Turing helper address
    function setTuringHelper(address _turingHelperAddress) public onlyOwner {
        turingHelperAddress = _turingHelperAddress;
        turing = TuringHelper(_turingHelperAddress);
    }

    // We want to attach the msg.sender address to the user's authorization code.
    // They are still unauthenticated at this point until the successfully call the `proveUser` function
    // This is to prevent any front running shenanigans
    function setUser(string memory _code) public {
        // Check if there is an existing address
        bool isUnset = unauthenticated[_code] == address(0);
        // Check if the current address has been there for more than 7 days
        bool weekOld = ((unauthenticatedTimestamp[_code] + 7 days) <
            block.timestamp);
        // We typically don't want to replace a users' set authorization code.
        // 7 days should be enough time for them call the `proveUser` function.
        // After that, it can be replaced to avoid squatting
        require(isUnset || weekOld, "Code is already set");
        // Record the time that this new code/address has been set
        unauthenticatedTimestamp[_code] = block.timestamp;
        // Set the code to the msg.sender
        unauthenticated[_code] = msg.sender;
    }

    // The user will submit a claim of what their Github account ID is, as well as their authorization code
    // This function uses turing to retrieve their Github account ID
    // If the account ID we retrieve is what they claimed it should be then we can safetly add their account ID/address to the authenticated mapping
    // Only one address can be mapped to the account ID, but that doesn't prevent it from being changed in the future
    function proveUser(uint256 _claim, string memory _code) public {
        // Check the address that was previously set with the `setUser` function and ensure we are dealing with the same caller
        require(
            unauthenticated[_code] == msg.sender,
            "You are only allowed to prove yourself"
        );
        // The turing request and response
        bytes memory encRequest = abi.encodePacked(_code);
        bytes memory encResponse = turing.TuringTx(url, encRequest);
        uint256 id = abi.decode(encResponse, (uint256));
        // check and make sure the ID that was claimed is the ID we got back from Turing
        require(id == _claim, "The claimed ID doesn't match");
        // We can now add the caller to the list of authenticated users.
        // An account ID can only have one address so it will overwrite any previous address
        authenticatedUsers[id] = msg.sender;
        // Remove the authorization code from our mapping since we no longer need to save it
        unauthenticated[_code] == address(0);
        // Emit the `Proved` event to show that this user was successfully proved
        emit Proved(msg.sender, id);
    }
}
