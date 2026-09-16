rule TTP_XOR_MULT_DOSStub_f20a {
  strings:
    $key_f20a = { a6 62 [2] d2 7a [2] 95 78 [2] d2 69 [2] 9c 65 [2] 90 6f [2] 87 64 [2] 9c 2a [2] a1 }

  condition:
    any of them
}