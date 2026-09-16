rule EquationGroup_gr_dev_bin_post {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "c1546155efa95dbc4e3cc95299a3968fc075f89d33164e78b00b76c7d08a0591"
      id = "9ec19323-85d5-5edf-99eb-b452c09b870a"
   strings:
      $x1 = "op=cron&action=once&frame=cronOnceFrame&cronK=cronV&cronCommand=%2Ftmp%2Ftmpwatch&time=12%3A12+01%2F28%2F2005" ascii
   condition:
      ( filesize < 1KB and all of them )
}