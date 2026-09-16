rule Gafgyt_Botnet_HIHI: MALW
{
meta:
description = "Gafgyt Trojan"
author = "Joan Soriano / @joanbtl"
date = "2017-05-01"
version = "1.0"
MD5 = "cc99e8dd2067fd5702a4716164865c8a"
SHA1 = "b9b316c1cc9f7a1bf8c70400861de08d95716e49"

    strings:
            $s1 = "PING"
            $s2 = "PONG"
            $s3 = "TELNET LOGIN CRACKED - %s:%s:%s"
            $s4 = "ADVANCEDBOT"
            $s5 = "46.166.185.92"
            $s6 = "LOLNOGTFO"

    condition:
            $s1 and $s2 and $s3 and $s4 and $s5 and $s6
}