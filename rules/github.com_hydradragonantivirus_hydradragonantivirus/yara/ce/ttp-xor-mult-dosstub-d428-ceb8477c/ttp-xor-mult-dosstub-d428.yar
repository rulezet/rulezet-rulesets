rule TTP_XOR_MULT_DOSStub_d428 {
  strings:
    $key_d428 = { 80 40 [2] f4 58 [2] b3 5a [2] f4 4b [2] ba 47 [2] b6 4d [2] a1 46 [2] ba 08 [2] 87 }

  condition:
    any of them
}