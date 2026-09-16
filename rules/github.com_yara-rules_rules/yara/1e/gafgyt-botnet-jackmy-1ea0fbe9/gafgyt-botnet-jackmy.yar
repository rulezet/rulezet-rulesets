rule Gafgyt_Botnet_jackmy : MALW
{
meta:
description = "Gafgyt Trojan"
author = "Joan Soriano / @joanbtl"
date = "2017-05-25"
version = "1.0"
MD5 = "419b8a10a3ac200e7e8a0c141b8abfba"
SHA1 = "5433a5768c5d22dabc4d133c8a1d192d525939d5"

    strings:
            $s1 = "PING"
            $s2 = "PONG"
            $s3 = "jackmy"         
            $s4 = "203.134.%d.%d"       
    condition:
            $s1 and $s2 and $s3 and $s4
}