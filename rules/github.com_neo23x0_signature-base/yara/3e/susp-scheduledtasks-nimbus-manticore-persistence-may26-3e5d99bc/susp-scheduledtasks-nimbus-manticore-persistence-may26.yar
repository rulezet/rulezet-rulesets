rule SUSP_ScheduledTasks_Nimbus_Manticore_Persistence_May26 {
   meta:
      description = "Detects scheduled task used for persistence by Nimbus Manticore (UNC1549). The task is used to persistenly load a custom implant that features data exfiltration and remote control capabilities."
      author = "Jonathan Peters (Nextron Systems)"
      date = "2026-05-27"
      reference = "https://www.nextron-systems.com/2026/06/01/detecting-nimbus-manticore-and-their-sideloading-infection-chains/"
      score = 75
   strings:
      $a0 = "<Task version=" wide
      $a1 = "xmlns=\"http://schemas.microsoft.com/windows/" wide

      $x1 = "<Arguments>doit" wide
   condition:
      uint16(0) == 0xfeff
      and all of them
}