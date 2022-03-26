# Swype bitcoin
### Create a raw P2WPKH Segwit transaction purely on client

### Steps:
1. Download the repo and open it in Xcode
2. Install required dependencies if required
3. Set the below constants to their appropriate values (line 613):
```swift
    let INPUT_TRX_ID = "d5832b04d8b3ffd871ef6da739de56f5d8408b6a161d61a19974106f40ef382d"
    let INPUT_BALANCE = UInt64(100000)
    let INPUT_INDEX = UInt32(0x0)
    let PUB_KEY = "038afc1c853d42d06312fc7585aadf168ffd990f23c935c81b3be7e77f17f979ce"
    let PRIVATE_KEY = "aea44f851ff6695f0027e63031cc9fd34507f1c82e55c8a19c8b1182ad1c7332"
    let INPUT_ADDRESS = "tb1qqg7h3z0pjmu9y55mszlyypqeek376ddlzphp9k"
```
    
4. Build and run the app on simulator

### Demo:
https://user-images.githubusercontent.com/37476411/160233785-56417d92-4546-486d-94cc-f8a31b6c0a3e.mov

