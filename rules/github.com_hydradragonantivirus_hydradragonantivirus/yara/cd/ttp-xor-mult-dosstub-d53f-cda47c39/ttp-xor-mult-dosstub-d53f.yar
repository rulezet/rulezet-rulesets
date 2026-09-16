rule TTP_XOR_MULT_DOSStub_d53f {
  strings:
    $key_d53f = { 81 57 [2] f5 4f [2] b2 4d [2] f5 5c [2] bb 50 [2] b7 5a [2] a0 51 [2] bb 1f [2] 86 }

  condition:
    any of them
}