rule TTP_XOR_MULT_DOSStub_d469 {
  strings:
    $key_d469 = { 80 01 [2] f4 19 [2] b3 1b [2] f4 0a [2] ba 06 [2] b6 0c [2] a1 07 [2] ba 49 [2] 87 }

  condition:
    any of them
}