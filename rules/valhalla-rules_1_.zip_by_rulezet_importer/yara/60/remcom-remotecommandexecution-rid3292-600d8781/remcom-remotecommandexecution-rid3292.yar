rule RemCom_RemoteCommandExecution_RID3292 : DEMO HKTL T1021_002 remcom {
   meta:
      description = "Detects strings from RemCom tool"
      author = "Florian Roth"
      reference = "https://www.virustotal.com/gui/file/3014995bdf04ed22452109136f759f7e83a5aab0cf2a79e6b787ac0f242c66c4/detection"
      date = "2017-12-28 14:10:51"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, HKTL, T1021_002, remcom"
      minimum_yara = "3.5.0"
      
   strings:
      $ = "\\\\.\\pipe\\%s%s%d" 
      $ = "%s\\pipe\\%s%s%d%s" 
      $ = "\\ADMIN$\\System32\\%s%s" 
   condition: 
      1 of them
}