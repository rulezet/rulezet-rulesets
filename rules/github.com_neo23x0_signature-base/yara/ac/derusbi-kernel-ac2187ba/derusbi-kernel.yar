rule derusbi_kernel
{
    meta:
        description = "Derusbi Driver version"
        date = "2015-12-09"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
        id = "a60ab93a-e2be-53ee-a7da-56c763bc5533"
    strings:
        $token1 = "$$$--Hello"
        $token2 = "Wrod--$$$"
        $class = ".?AVPCC_BASEMOD@@"
    condition:
        uint16(0) == 0x5A4D and $token1 and $token2 and $class
}