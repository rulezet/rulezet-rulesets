rule TTP_XOR_MULT_DOSStub_e52a {
  strings:
    $key_e52a = { b1 42 [2] c5 5a [2] 82 58 [2] c5 49 [2] 8b 45 [2] 87 4f [2] 90 44 [2] 8b 0a [2] b6 }

  condition:
    any of them
}