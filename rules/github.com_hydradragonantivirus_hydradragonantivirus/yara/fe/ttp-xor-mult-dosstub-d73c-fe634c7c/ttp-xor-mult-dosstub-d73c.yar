rule TTP_XOR_MULT_DOSStub_d73c {
  strings:
    $key_d73c = { 83 54 [2] f7 4c [2] b0 4e [2] f7 5f [2] b9 53 [2] b5 59 [2] a2 52 [2] b9 1c [2] 84 }

  condition:
    any of them
}