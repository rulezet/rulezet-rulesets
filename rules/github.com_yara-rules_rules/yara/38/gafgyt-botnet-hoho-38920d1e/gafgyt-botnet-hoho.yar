rule Gafgyt_Botnet_hoho : MALW
{
meta:
description = "Gafgyt Trojan"
author = "Joan Soriano / @joanbtl"
date = "2017-05-25"
version = "1.0"
MD5 = "369c7c66224b343f624803d595aa1e09"
SHA1 = "54519d2c124cb536ed0ddad5683440293d90934f"

    strings:
            $s1 = "PING"
            $s2 = "PRIVMSG"
            $s3 = "Remote IRC Bot"
            $s4 = "23.95.43.182"
    condition:
            $s1 and $s2 and $s3 and $s4
}