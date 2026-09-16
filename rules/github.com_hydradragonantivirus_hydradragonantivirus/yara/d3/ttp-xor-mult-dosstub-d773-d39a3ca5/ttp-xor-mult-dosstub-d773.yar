rule TTP_XOR_MULT_DOSStub_d773 {
  strings:
    $key_d773 = { 83 1b [2] f7 03 [2] b0 01 [2] f7 10 [2] b9 1c [2] b5 16 [2] a2 1d [2] b9 53 [2] 84 }

  condition:
    any of them
}