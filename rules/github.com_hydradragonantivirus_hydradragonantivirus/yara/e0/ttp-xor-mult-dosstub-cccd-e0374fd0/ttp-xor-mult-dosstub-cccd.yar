rule TTP_XOR_MULT_DOSStub_cccd {
  strings:
    $key_cccd = { 98 a5 [2] ec bd [2] ab bf [2] ec ae [2] a2 a2 [2] ae a8 [2] b9 a3 [2] a2 ed [2] 9f }

  condition:
    any of them
}