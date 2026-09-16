rule TTP_XOR_MULT_DOSStub_e71a {
  strings:
    $key_e71a = { b3 72 [2] c7 6a [2] 80 68 [2] c7 79 [2] 89 75 [2] 85 7f [2] 92 74 [2] 89 3a [2] b4 }

  condition:
    any of them
}