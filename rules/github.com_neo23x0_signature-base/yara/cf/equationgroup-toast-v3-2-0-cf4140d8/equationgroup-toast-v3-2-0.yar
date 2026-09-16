rule EquationGroup_toast_v3_2_0 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file toast_v3.2.0.1-linux"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "2ce2d16d24069dc29cf1464819a9dc6deed38d1e5ffc86d175b06ddb691b648b"
      id = "776014ae-be94-5d81-bceb-fefb67ee1994"
   strings:
      $x2 = "Del --- Usage: %s -l file -w wtmp -r user" fullword ascii
      $s5 = "Roasting ->%s<- at ->%d:%d<-" ascii
      $s6 = "rbnoil -Roasting ->" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and 1 of them )
}