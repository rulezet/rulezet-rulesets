rule TTP_XOR_MULT_DOSStub_e72a {
  strings:
    $key_e72a = { b3 42 [2] c7 5a [2] 80 58 [2] c7 49 [2] 89 45 [2] 85 4f [2] 92 44 [2] 89 0a [2] b4 }

  condition:
    any of them
}