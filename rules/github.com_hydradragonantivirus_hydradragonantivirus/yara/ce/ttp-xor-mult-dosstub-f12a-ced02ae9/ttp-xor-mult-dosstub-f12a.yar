rule TTP_XOR_MULT_DOSStub_f12a {
  strings:
    $key_f12a = { a5 42 [2] d1 5a [2] 96 58 [2] d1 49 [2] 9f 45 [2] 93 4f [2] 84 44 [2] 9f 0a [2] a2 }

  condition:
    any of them
}