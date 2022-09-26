# PMS Judge Protocol Library
## Handshake Process
우선 slave 노드의 키 $k_s$와 master 노드의 키 $k_m$이 처음에 생성되었다고 가정. (아마 시작마다 RNG 돌려서 생성하는 구현으로 갈듯)

그리고, 각각의 공개키는 $k_{s}^{p}$, $k_{m}^{p}$임.

`HANDSHAKE` 패킷을 slave에서 master로 먼저 $k_{s}^{p}$를 보내고, master는 이 패킷을 받은 뒤 slave로 `HANDSHAKE` 패킷을 통해서 $k_{m}^{p}$를 보냄.

그리고 slave와 master 모두 `secp256k1` 타원곡선을 이용해서 ECDH로 공유 키 $k$를 만듦.

그리고 slave는 $k || k_{s}^{p}$로 구성된 토큰 $t$을 만들어서 가지고 있음. (그리고 $|k_s| = |k_m|$으로 고정이고 아마 128비트로 할듯)

## Verify Token
slave가 `VERIFY_TOKEN` 커맨드로 $t$를 보내면 master는 그걸 받아서 $k_{s}^{p}$를 이용해서 공유 키 $k^{\prime}$를 만들고 그게 $k$랑 동일한지 검사. 그 여부를 `REQ_VERIFY_TOKEN`으로 반환해줌.

## Login Process
master 노드가 설정 파일에 개인 키를 가지고 있고, slave 노드는 이 키를 가지고 로그인을 시도해야함.

`GET_LOGIN` 커맨드로 `body`에 개인 키를 담아서 slave 노드에서 보내면, master 노드는 `REQ_LOGIN` 커맨드로 이에 대한 정답 여부를 검사함. (* 아마 구현마다 달라질 수 있는데, 개인 키는 우선 그 자체의 평문 유출을 막기 위해서 Handshake 과정에서 교환한 키로 암호화해서 보내는걸로 구현하는걸 권장. **단, Handshake가 유효한 상황일때 암호화된 개인 키 자체가 서버 입장에서는 평문과 다름 없다는 것을 명심하라.**)

