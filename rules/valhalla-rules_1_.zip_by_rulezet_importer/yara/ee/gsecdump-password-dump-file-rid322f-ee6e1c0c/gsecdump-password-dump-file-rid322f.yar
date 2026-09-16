rule Gsecdump_password_dump_file_RID322F : DEMO FILE SUSP T1003 {
   meta:
      description = "Detects a gsecdump output file"
      author = "Florian Roth"
      reference = "https://t.co/OLIj1yVJ4m"
      date = "2018-03-06 13:54:21"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, SUSP, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Administrator(current):500:" ascii
   condition: 
      uint32be ( 0 ) == 0x41646d69 and filesize < 3000 and $x1 at 0
}