rule EquationGroup_dumppoppy {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file dumppoppy"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "4a5c01590063c78d03c092570b3206fde211daaa885caac2ab0d42051d4fc719"
      id = "c316aac3-bdd7-5187-8ae2-0a87c2f2d26f"
   strings:
      $x1 = "Unless the -c (clobber) option is used, if two RETR commands of the" fullword ascii
      $x2 = "mywarn(\"End of $destfile determined by \\\"^Connection closed by foreign host\\\"\")" fullword ascii

      $l1 = "End of $destfile determined by \"^Connection closed by foreign host"
   condition:
      ( filesize < 20KB and 1 of them )
}