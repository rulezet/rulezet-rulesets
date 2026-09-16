rule Empire_lib_modules_credentials_mimikatz_pth_RID38BE : DEMO S0002 SCRIPT SUSP T1003 T1059_001 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Empire - a pure PowerShell post-exploitation agent - file pth.py"
      author = "Florian Roth"
      reference = "https://github.com/PowerShellEmpire/Empire"
      date = "2015-08-06 18:34:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, S0002, SCRIPT, SUSP, T1003, T1059_001, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "(credID, credType, domainName, userName, password, host, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]" fullword ascii
      $s1 = "command = \"sekurlsa::pth /user:\"+self.options[\"user\"]['Value']" fullword ascii
   condition: 
      filesize < 12KB and all of them
}