import "pe"
rule Datper_Backdoor_RID2CF5 : DEMO EXE FILE MAL {
   meta:
      description = "Detects Datper Malware"
      author = "Florian Roth"
      reference = "http://blog.jpcert.or.jp/2017/08/detecting-datper-malware-from-proxy-logs.html"
      date = "2017-08-21 10:11:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7d70d659c421b50604ce3e0a1bf423ab7e54b9df361360933bac3bb852a31849"
      hash2 = "331ac0965b50958db49b7794cc819b2945d7b5e5e919c185d83e997e205f107b"
      hash3 = "90ac1fb148ded4f46949a5fea4cd8c65d4ea9585046d66459328a5866f8198b2"
      tags = "DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "RtlGetCo" fullword ascii
      $s2 = "hutils" fullword ascii
      $s3 = "kza2FWU,f;\"3U&zpa3U(W`J" fullword ascii
      $c1 = "dkkwldngn" fullword ascii
      $c2 = "ndkkwqgcm" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "58db98e2334746d349d607e4d73bc5ea" or pe.imphash ( ) == "8fbed921458af485ce84fb7d9b13899e" or ( 2 of ( $s* ) and 1 of ( $c* ) ) or ( $s3 and $c1 ) ) )
}