rule HKTL_MAL_Churrasco_Jun16_RID2F79 : CHINA DEMO EXE FILE HKTL MAL {
   meta:
      description = "Chinese Hacktool Set - file churrasco.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:58:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Done, command should have ran as SYSTEM!" ascii
      $s2 = "Running command with SYSTEM Token..." ascii
      $s3 = "Thread impersonating, got NETWORK SERVICE Token: 0x%x" ascii
      $s4 = "Found SYSTEM token 0x%x" ascii
      $s5 = "Thread not impersonating, looking for another thread..." ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 150KB and 2 of them
}