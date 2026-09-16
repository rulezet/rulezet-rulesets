rule EquationGroup_watcher_solaris_i386_v_3_3_0_RID36FE : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 17:19:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "395ec2531970950ffafde234dded0cce0c95f1f9a22763d1d04caa060a5222bb"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "getexecname" fullword ascii
      $s2 = "invalid option `" fullword ascii
      $s6 = "__fpstart" ascii
      $s12 = "GHFIJKLMNOPQRSTUVXW" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 700KB and all of them )
}