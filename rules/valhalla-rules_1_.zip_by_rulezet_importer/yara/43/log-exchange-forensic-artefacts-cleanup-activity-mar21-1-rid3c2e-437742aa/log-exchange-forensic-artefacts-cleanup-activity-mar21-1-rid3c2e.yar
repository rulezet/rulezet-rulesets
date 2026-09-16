rule LOG_Exchange_Forensic_Artefacts_CleanUp_Activity_Mar21_1_RID3C2E : DEMO G0125 LOG {
   meta:
      description = "Detects forensic artefacts showing cleanup activity found in HAFNIUM intrusions exploiting"
      author = "Florian Roth"
      reference = "https://twitter.com/jdferrell3/status/1368626281970024448"
      date = "2021-03-08 21:00:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, G0125, LOG"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "cmd.exe /c cd /d C:/inetpub/wwwroot/aspnet_client" ascii wide
      $x2 = "cmd.exe /c cd /d C:\\inetpub\\wwwroot\\aspnet_client" ascii wide
      $s1 = "aspnet_client&del '" 
      $s2 = "aspnet_client&attrib +h +s +r " 
      $s3 = "&echo [S]" 
   condition: 
      1 of ( $x* ) or 2 of them
}