rule TTP_XOR_MULT_DOSStub_f10a {
  strings:
    $key_f10a = { a5 62 [2] d1 7a [2] 96 78 [2] d1 69 [2] 9f 65 [2] 93 6f [2] 84 64 [2] 9f 2a [2] a2 }

  condition:
    any of them
}