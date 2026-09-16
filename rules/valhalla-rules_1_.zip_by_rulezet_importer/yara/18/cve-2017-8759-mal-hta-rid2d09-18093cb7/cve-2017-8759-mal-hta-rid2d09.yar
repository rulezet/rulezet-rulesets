rule CVE_2017_8759_Mal_HTA_RID2D09 : CVE_2017_8759 DEMO EXPLOIT FILE MAL T1203 T1566_001 {
   meta:
      description = "Detects malicious files related to CVE-2017-8759 - file cmd.hta"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14 10:14:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fee2ab286eb542c08fdfef29fabf7796a0a91083a0ee29ebae219168528294b5"
      tags = "CVE_2017_8759, DEMO, EXPLOIT, FILE, MAL, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Error = Process.Create(\"powershell -nop cmd.exe /c" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x683c and filesize < 1KB and all of them )
}