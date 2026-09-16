rule Gafgyt_Botnet_oh : MALW
{
meta:
description = "Gafgyt Trojan"
author = "Joan Soriano / @joanbtl"
date = "2017-05-025"
version = "1.0"
MD5 = "97f5edac312de349495cb4afd119d2a5"
SHA1 = "916a51f2139f11e8be6247418dca6c41591f4557"

    strings:
            $s1 = "busyboxterrorist"
            $s2 = "BOGOMIPS"
            $s3 = "124.105.97.%d"
            $s4 = "fucknet"
    condition:
            $s1 and $s2 and $s3 and $s4
}