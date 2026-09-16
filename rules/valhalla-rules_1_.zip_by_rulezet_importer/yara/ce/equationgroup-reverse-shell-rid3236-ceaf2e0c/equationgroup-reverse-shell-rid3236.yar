rule EquationGroup_reverse_shell_RID3236 : APT DEMO G0020 SCRIPT {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file reverse.shell.script"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:55:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d29aa24e6fb9e3b3d007847e1630635d6c70186a36c4ab95268d28aa12896826"
      tags = "APT, DEMO, G0020, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "sh >/dev/tcp/" ascii
      $s2 = " <&1 2>&1" fullword ascii
   condition: 
      ( filesize < 1KB and all of them )
}