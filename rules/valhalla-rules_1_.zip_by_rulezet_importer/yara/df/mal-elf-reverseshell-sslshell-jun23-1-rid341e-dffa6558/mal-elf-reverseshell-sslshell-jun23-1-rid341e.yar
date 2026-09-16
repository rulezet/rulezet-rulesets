rule MAL_ELF_ReverseShell_SSLShell_Jun23_1_RID341E : CVE_2023_2868 DEMO FILE LINUX MAL SCRIPT {
   meta:
      description = "Detects a reverse shell named SSLShell used in Barracuda ESG exploitation (CVE-2023-2868)"
      author = "Florian Roth"
      reference = "https://www.barracuda.com/company/legal/esg-vulnerability"
      date = "2023-06-07 15:16:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8849a3273e0362c45b4928375d196714224ec22cb1d2df5d029bf57349860347"
      tags = "CVE_2023_2868, DEMO, FILE, LINUX, MAL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $sc1 = { 00 2D 63 00 2F 62 69 6E 2F 73 68 00 } 
      $s1 = "SSLShell" 
   condition: 
      uint32be ( 0 ) == 0x7f454c46 and uint16 ( 0x10 ) == 0x0002 and filesize < 5MB and all of them
}