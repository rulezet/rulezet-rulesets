rule SUSP_MAL_SigningCert_Feb24_1_RID30B3 : CVE_2024_1708 CVE_2024_1709 DEMO EXE FILE MAL SUSP {
   meta:
      description = "Detects PE files signed with a certificate used to sign malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23 12:51:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "37a39fc1feb4b14354c4d4b279ba77ba51e0d413f88e6ab991aad5dd6a9c231b"
      hash2 = "e8c48250cf7293c95d9af1fb830bb8a5aaf9cfb192d8697d2da729867935c793"
      tags = "CVE_2024_1708, CVE_2024_1709, DEMO, EXE, FILE, MAL, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Wisdom Promise Security Technology Co." ascii
      $s2 = "Globalsign TSA for CodeSign1" ascii
      $s3 = { 5D AC 0B 6C 02 5A 4B 21 89 4B A3 C2 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 70000KB and all of them
}