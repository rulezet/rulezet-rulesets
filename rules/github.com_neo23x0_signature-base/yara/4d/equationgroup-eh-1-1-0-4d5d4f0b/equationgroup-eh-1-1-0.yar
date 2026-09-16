rule EquationGroup_eh_1_1_0 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file eh.1.1.0.0"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "0f8dd094516f1be96da5f9addc0f97bcac8f2a348374bd9631aa912344559628"
      id = "a6f0ec1f-b0e5-5913-970d-9cdadf647c44"
   strings:
      $x1 = "usage: %s -e -v -i target IP [-c Cert File] [-k Key File]" fullword ascii
      $x2 = "TYPE=licxfer&ftp=%s&source=/var/home/ftp/pub&version=NA&licfile=" ascii
      $x3 = "[-l Log File] [-m save MAC time file(s)] [-p Server Port]" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 100KB and 1 of them )
}