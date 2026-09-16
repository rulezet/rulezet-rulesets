rule TTP_XOR_MULT_DOSStub_d413 {
  strings:
    $key_d413 = { 80 7b [2] f4 63 [2] b3 61 [2] f4 70 [2] ba 7c [2] b6 76 [2] a1 7d [2] ba 33 [2] 87 }

  condition:
    any of them
}