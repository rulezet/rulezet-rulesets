rule infected_107_175_218_241_2018_10_14a_shells_dc2 {
  meta:
    description = "shells - file dc2.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-10-28"
    hash1       = "07f20c09a3b101ef7523ea996e2eb3f3e28d022dc8e966e497a3fb3efc22e302"

  strings:
    $s1  = "en0afpiOQ52UuurOpovfl7pj4pLK4k4IjCNghCQunCTLRY3u1DqzA3Ga0uYbgBQ9DPnYQEXecIGcObYp" fullword ascii
    $s2  = "tDEU6AwuJgUL+QanaAbcqH8JT2i9TxDPBLh9mgjMSk/YAqRW9qHi9jndQUwlnpTIRcVrHPzAyQqm5Zfg" fullword ascii
    $s3  = "$s6353 = $wxsE7559($AE1718(\"pX1Nb+PK0t5f4XDmHknXkizq05YsjT22PKMc2/IryXfOeceGQJGUxGOJ5CUpW3N8DWSTRTYBkkUQIPsA" fullword ascii
    $s4  = "5oonn/8pCmR36EYEKYXD6clqxbeATVH/9UriH/75vw==\")); print ($s6353);" fullword ascii
    $s5  = "$AE1718 = chr(98).\"a\".chr(115).\"\".chr(101).\"\\x364_d\\x65c\\x6F\\x64\".chr(101);" fullword ascii
    $s6  = "pXkzJiiBf7DZ0KBFmOHiFP89v7oGjvYDsH8VnszIKEYxHDPwH9OPAT9F74g2tAoj2M2RtWWDCcS6aOuz" fullword ascii
    $s7  = "92ZD26sf1ivNvRJ9rDQw+xzuYBdajLhsnxCCJuigsse/GdI3vkTAVt+GRMx9UN/j3zuQtMphtVpuyv9a" fullword ascii
    $s8  = "L3/r4gkOkGeCmdmIKPrh05GyKxxbr6SD0P/v0V10ElgchjXC+HBZzsv1sscjcsLpkuudgcPxeLQfn3YQ" fullword ascii
    $s9  = "<?php $wxsE7559 = chr(103).\"\\x7a\\x69\\x6e\\x66\".chr(108).\"\\x61te\";" fullword ascii
    $s10 = "2HRCrlJTkc6w8YhKYpA9sYbgC4Xs4wyEB8tXBtdCCgDbWAJHiRXi7/Tk7HZbr48wzRAJEYeSYVAnIWXR" fullword ascii
    $s11 = "sMQ//Jf/8N9FWsUTJ2Tkx5vZeOJzUfG1/Akc9t1XsfMx1m38EqkLgh/6kh+QpSG4ARP/565vnZgcSGYu" fullword ascii
    $s12 = "lU9tux3w1MwQH7B4jsl4m/6T//Vf+akg+ELCPEd0qfEaFcnsjBr5j1GjPHy+KEC0nmC9F6IIJfso+GOe" fullword ascii
    $s13 = "JiSdqve//+W/+m957Dpo+djB9LNvT/QPq356BcInaTJLKaxfpNLIsdaABdXLU7PQIkpg3gqR3mhTfalz" fullword ascii
    $s14 = "Ja2EI6nFO/vQiuHPB6v+tTW6/AZ8JUYXYKJDGjBM31bJatpB9Lo/ugzSgNigCrPus3//z6iG7d67IjHj" fullword ascii
    $s15 = "iI8iPPFHBoInzFX+gx70r07WFjdEZ+WyijPLMxrAlb7uJ+XEpDhVZjsbi/r/83LZpRnpYwMk6gjTGOWk" fullword ascii
    $s16 = "0/XJxPiUV/fV8m+u7eTVv6hF0W2hrO7beElheKtVK7tIfuqfnPX9PH2+3Tbq17fb6lwrV5R6pa5cueFt" fullword ascii
    $s17 = "r/RTVNs2DFmNa2CQePpCK+zCuuLnQim9mMq1zH97PywoYIS3lUZLjLLcpd46iYT4n//0X+R5PiKNKwmz" fullword ascii
    $s18 = "AEmSHWEc8l3bZCu2fyBKiT0mwwyXBXFKBfMoM9ZkuDn9HiMLbjrX+WSFTE5SuGzCfmhjScJN3qUjyj/o" fullword ascii
    $s19 = "g/HUHIzyoqCstjliR/QWPYBLK636y8FAzsjx0DtmJZ+br2kEKhmO4P4Q3C96Iaj7bPLBIdn8Al+z7A0W" fullword ascii
    $s20 = "M/4h5bE7K7xfY4iYFAPb1bqkXzREMrQ1jNLBrqvZyFhjafBMQGzRduedpqiapiGwTnfwVYFnl8moJROk" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 50KB and
      (8 of them)
    ) or (all of them)
}