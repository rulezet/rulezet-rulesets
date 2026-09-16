rule TTP_XOR_MULT_DOSStub_d51c {
  strings:
    $key_d51c = { 81 74 [2] f5 6c [2] b2 6e [2] f5 7f [2] bb 73 [2] b7 79 [2] a0 72 [2] bb 3c [2] 86 }

  condition:
    any of them
}