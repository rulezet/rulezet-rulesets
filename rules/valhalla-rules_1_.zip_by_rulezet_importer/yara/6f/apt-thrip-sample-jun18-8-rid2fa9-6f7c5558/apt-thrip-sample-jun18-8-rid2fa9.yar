rule APT_Thrip_Sample_Jun18_8_RID2FA9 : APT DEMO G0030 G0076 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21 12:06:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0f2d09b1ad0694f9e71eeebec5b2d137665375bf1e76cb4ae4d7f20487394ed3"
      tags = "APT, DEMO, G0030, G0076"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "$.oS.Run('cmd.exe /c '+a+'" fullword ascii
      $x2 = "new $._x('WScript.Shell');" ascii
      $x3 = ".ExpandEnvironmentStrings('%Temp%')+unescape('" ascii
   condition: 
      filesize < 10KB and 1 of ( $x* )
}