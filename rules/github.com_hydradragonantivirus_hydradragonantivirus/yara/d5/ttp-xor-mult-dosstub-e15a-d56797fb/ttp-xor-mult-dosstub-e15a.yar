rule TTP_XOR_MULT_DOSStub_e15a {
  strings:
    $key_e15a = { b5 32 [2] c1 2a [2] 86 28 [2] c1 39 [2] 8f 35 [2] 83 3f [2] 94 34 [2] 8f 7a [2] b2 }

  condition:
    any of them
}