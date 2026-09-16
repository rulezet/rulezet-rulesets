rule TTP_XOR_MULT_DOSStub_d52c {
  strings:
    $key_d52c = { 81 44 [2] f5 5c [2] b2 5e [2] f5 4f [2] bb 43 [2] b7 49 [2] a0 42 [2] bb 0c [2] 86 }

  condition:
    any of them
}