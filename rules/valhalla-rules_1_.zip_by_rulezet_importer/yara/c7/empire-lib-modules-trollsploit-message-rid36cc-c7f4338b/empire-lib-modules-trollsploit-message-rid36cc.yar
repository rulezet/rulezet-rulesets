rule Empire_lib_modules_trollsploit_message_RID36CC : DEMO SCRIPT SUSP T1059_001 {
   meta:
      description = "Empire - a pure PowerShell post-exploitation agent - file message.py"
      author = "Florian Roth"
      reference = "https://github.com/PowerShellEmpire/Empire"
      date = "2015-08-06 17:11:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, SUSP, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "script += \" -\" + str(option) + \" \\\"\" + str(values['Value'].strip(\"\\\"\")) + \"\\\"\"" fullword ascii
      $s2 = "if option.lower() != \"agent\" and option.lower() != \"computername\":" fullword ascii
      $s3 = "[String] $Title = 'ERROR - 0xA801B720'" fullword ascii
      $s4 = "'Value'         :   'Lost contact with the Domain Controller.'" fullword ascii
   condition: 
      filesize < 10KB and 3 of them
}