import "pe"
rule Ran_Cert_RagnarLocker_Nov_2020_1 {
   meta:
      description = "Detect certificates and VMProtect used for the Ragnarlocker ransomware (Nov 2020)"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-11-26"
      level = "Experimental"
      hash1 = "afab912c41c920c867f1b2ada34114b22dcc9c5f3666edbfc4e9936c29a17a68"
      hash2 = "9416e5a57e6de00c685560fa9fee761126569d123f62060792bf2049ebba4151"
   strings:
     $vmp0 = { 2E 76 6D 70 30 00 00 00 }
     $vmp1 = { 2E 76 6D 70 31 00 00 00 }
   condition:
      uint16(0) == 0x5a4d and filesize > 5000KB and 
      for any i in (0 .. pe.number_of_signatures) : (
               pe.signatures[i].issuer contains "GlobalSign" and
               pe.signatures[i].serial == "68:65:29:4f:67:f0:c3:bb:2e:19:1f:75"
            )
            and $vmp0 in (0x100..0x300) and $vmp1 in (0x100..0x300)
}