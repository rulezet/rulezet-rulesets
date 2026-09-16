rule TTP_XOR_MULT_DOSStub_d473 {
  strings:
    $key_d473 = { 80 1b [2] f4 03 [2] b3 01 [2] f4 10 [2] ba 1c [2] b6 16 [2] a1 1d [2] ba 53 [2] 87 }

  condition:
    any of them
}