rule TTP_XOR_MULT_DOSStub_d52d {
  strings:
    $key_d52d = { 81 45 [2] f5 5d [2] b2 5f [2] f5 4e [2] bb 42 [2] b7 48 [2] a0 43 [2] bb 0d [2] 86 }

  condition:
    any of them
}