rule Webshell_JFolder_Leo_RID2ECB : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:29:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a7e25b8ac605753ed0c438db93f6c498"
      hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
      hash3 = "36331f2c81bad763528d0ae00edf55be"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "UplInfo info = UploadMonitor.getInfo(fi.clientFileName);" fullword
      $s5 = "long time = (System.currentTimeMillis() - starttime) / 1000l;" fullword
   condition: 
      all of them
}