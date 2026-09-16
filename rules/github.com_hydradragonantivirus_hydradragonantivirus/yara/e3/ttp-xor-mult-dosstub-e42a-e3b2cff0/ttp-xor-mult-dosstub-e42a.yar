rule TTP_XOR_MULT_DOSStub_e42a {
  strings:
    $key_e42a = { b0 42 [2] c4 5a [2] 83 58 [2] c4 49 [2] 8a 45 [2] 86 4f [2] 91 44 [2] 8a 0a [2] b7 }

  condition:
    any of them
}