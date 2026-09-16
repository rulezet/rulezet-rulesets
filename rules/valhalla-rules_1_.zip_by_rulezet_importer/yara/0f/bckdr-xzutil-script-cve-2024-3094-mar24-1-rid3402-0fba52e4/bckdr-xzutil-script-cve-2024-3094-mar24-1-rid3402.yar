rule BCKDR_XZUtil_Script_CVE_2024_3094_Mar24_1_RID3402 : CVE_2024_3094 DEMO SCRIPT {
   meta:
      description = "Detects make file and script contents used by the backdoored XZ library (xzutil) CVE-2024-3094."
      author = "Florian Roth"
      reference = "https://www.openwall.com/lists/oss-security/2024/03/29/4"
      date = "2024-03-30 15:12:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2024_3094, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "/bad-3-corrupt_lzma2.xz | tr " ascii
      $x2 = "/tests/files/good-large_compressed.lzma|eval $i|tail -c +31265|" ascii
      $x3 = "eval $zrKcKQ" ascii
   condition: 
      1 of them
}