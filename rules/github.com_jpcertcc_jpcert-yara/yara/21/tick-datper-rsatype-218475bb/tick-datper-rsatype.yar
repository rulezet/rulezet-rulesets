rule tick_Datper_RSAtype {
      meta:
        description = "Datper malware (RSA type)"
        author = "JPCERT/CC Incident Response Group"

      strings:
         $a1 = { E8 03 00 00 }
         $b1 = "|||"
         $c1 = "Content-Type: application/x-www-form-urlencoded"
         $d1 = { A8 03 10 00 FF FF FF FF }
         $push7530h64 = { C7 C1 30 75 00 00 }
         $push7530h = { 68 30 75 00 00 }

      condition:
        $a1 and $b1 and $c1 and $d1 and ($push7530h64 or $push7530h)
}