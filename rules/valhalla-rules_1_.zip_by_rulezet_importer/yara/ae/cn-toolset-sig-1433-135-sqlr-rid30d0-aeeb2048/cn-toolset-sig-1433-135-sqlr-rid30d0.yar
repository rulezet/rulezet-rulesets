rule CN_Toolset_sig_1433_135_sqlr_RID30D0 : CHINA DEMO HKTL {
   meta:
      description = "Detects a Chinese hacktool from a disclosed toolset - file sqlr.exe"
      author = "Florian Roth"
      reference = "http://qiannao.com/ls/905300366/33834c0c/"
      date = "2015-03-30 12:55:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Connect to %s MSSQL server success. Type Command at Prompt." fullword ascii
      $s11 = ";DATABASE=master" fullword ascii
      $s12 = "xp_cmdshell '" fullword ascii
      $s14 = "SELECT * FROM OPENROWSET('SQLOLEDB','Trusted_Connection=Yes;Data Source=myserver" ascii
   condition: 
      all of them
}