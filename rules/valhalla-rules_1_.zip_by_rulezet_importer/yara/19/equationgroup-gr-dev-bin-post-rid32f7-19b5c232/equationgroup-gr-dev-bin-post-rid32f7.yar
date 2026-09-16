rule EquationGroup_gr_dev_bin_post_RID32F7 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 14:27:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c1546155efa95dbc4e3cc95299a3968fc075f89d33164e78b00b76c7d08a0591"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "op=cron&action=once&frame=cronOnceFrame&cronK=cronV&cronCommand=%2Ftmp%2Ftmpwatch&time=12%3A12+01%2F28%2F2005" ascii
   condition: 
      ( filesize < 1KB and all of them )
}