rule WiltedTulip_Tools_clrlg_RID306B : APT DEMO SCRIPT {
   meta:
      description = "Detects Windows eventlog cleaner used in Operation Wilted Tulip - file clrlg.bat"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23 12:39:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b33fd3420bffa92cadbe90497b3036b5816f2157100bf1d9a3b6c946108148bf"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "('wevtutil.exe el') DO (call :do_clear" fullword ascii
      $s2 = "wevtutil.exe cl %1" fullword ascii
   condition: 
      filesize < 1KB and 1 of them
}