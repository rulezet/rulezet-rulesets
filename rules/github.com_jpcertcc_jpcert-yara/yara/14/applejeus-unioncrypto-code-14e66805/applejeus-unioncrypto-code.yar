rule AppleJeus_UnionCrypto_code {
     meta:
        description = "UnionCrypto malware in AppleJeus"
        author = "JPCERT/CC Incident Response Group"
        hash = "295c20d0f0a03fd8230098fade0af910b2c56e9e5700d4a3344d10c106a6ae2a"

     strings:
        $http1 = "auth_timestamp:" ascii
        $http2 = "auth_signature:" ascii
        $http3 = "&act=check" ascii
        $http4 = "Windows %d(%d)-%s" ascii
        $key = "vG2eZ1KOeGd2n5fr" ascii

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (all of ($http*) or $key)
}