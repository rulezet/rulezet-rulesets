rule Hacktools_CN_Burst_Clear_RID305E : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Disclosed hacktool set - file Clear.bat"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-17 12:36:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "del /f /s /q %systemdrive%\\*.log    " fullword ascii
      $s1 = "del /f /s /q %windir%\\*.bak    " fullword ascii
      $s4 = "del /f /s /q %systemdrive%\\*.chk    " fullword ascii
      $s5 = "del /f /s /q %systemdrive%\\*.tmp    " fullword ascii
      $s8 = "del /f /q %userprofile%\\COOKIES s\\*.*    " fullword ascii
      $s9 = "rd /s /q %windir%\\temp & md %windir%\\temp    " fullword ascii
      $s11 = "del /f /s /q %systemdrive%\\recycled\\*.*    " fullword ascii
      $s12 = "del /f /s /q \"%userprofile%\\Local Settings\\Temp\\*.*\"    " fullword ascii
      $s19 = "del /f /s /q \"%userprofile%\\Local Settings\\Temporary Internet Files\\*.*\"   " ascii
   condition: 
      5 of them
}