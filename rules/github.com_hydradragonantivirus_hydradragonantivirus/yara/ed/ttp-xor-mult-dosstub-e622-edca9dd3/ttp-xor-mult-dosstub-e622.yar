rule TTP_XOR_MULT_DOSStub_e622 {
  strings:
    $key_e622 = { b2 4a [2] c6 52 [2] 81 50 [2] c6 41 [2] 88 4d [2] 84 47 [2] 93 4c [2] 88 02 [2] b5 }

  condition:
    any of them
}