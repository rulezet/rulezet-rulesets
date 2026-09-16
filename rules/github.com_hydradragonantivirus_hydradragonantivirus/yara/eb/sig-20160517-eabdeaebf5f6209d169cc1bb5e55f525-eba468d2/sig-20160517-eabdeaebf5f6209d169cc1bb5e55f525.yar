rule sig_20160517_eabdeaebf5f6209d169cc1bb5e55f525 {
  meta:
    description = "datamaliciousorder - file 20160517_eabdeaebf5f6209d169cc1bb5e55f525.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb85d697c8098e87bcc912b4ba1dc151362105f40fa3f31c74e5aa62fb7e195d"

  strings:
    $s1 = "var ba2xvp='vjdpa2apd4mfrag42u vtfqnqpql1bgssn2bkmujgyinrcodblcopefqq2shbgm2anwnrfvtwnmnyxvwior2=oddkw\\'yxnoptucc1hcwd344noopjm" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}