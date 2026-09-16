rule TTP_XOR_MULT_DOSStub_e51a {
  strings:
    $key_e51a = { b1 72 [2] c5 6a [2] 82 68 [2] c5 79 [2] 8b 75 [2] 87 7f [2] 90 74 [2] 8b 3a [2] b6 }

  condition:
    any of them
}