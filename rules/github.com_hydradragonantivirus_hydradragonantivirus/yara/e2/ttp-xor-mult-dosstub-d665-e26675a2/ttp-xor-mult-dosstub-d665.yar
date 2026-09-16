rule TTP_XOR_MULT_DOSStub_d665 {
  strings:
    $key_d665 = { 82 0d [2] f6 15 [2] b1 17 [2] f6 06 [2] b8 0a [2] b4 00 [2] a3 0b [2] b8 45 [2] 85 }

  condition:
    any of them
}