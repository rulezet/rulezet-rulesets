rule TTP_XOR_MULT_DOSStub_e12a {
  strings:
    $key_e12a = { b5 42 [2] c1 5a [2] 86 58 [2] c1 49 [2] 8f 45 [2] 83 4f [2] 94 44 [2] 8f 0a [2] b2 }

  condition:
    any of them
}