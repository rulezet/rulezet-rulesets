rule CN_Honker_ChinaChopper_RID2F7B : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file ChinaChopper.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:59:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$m=get_magic_quotes_gpc();$sid=$m?stripslashes($_POST[\"z1\"]):$_POST[\"z1\"];$u" wide
      $s3 = "SETP c:\\windows\\system32\\cmd.exe " fullword wide
      $s4 = "Ev al (\"Exe cute(\"\"On+Error+Resume+Next:%s:Response.Write(\"\"\"\"->|\"\"\"\"" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}