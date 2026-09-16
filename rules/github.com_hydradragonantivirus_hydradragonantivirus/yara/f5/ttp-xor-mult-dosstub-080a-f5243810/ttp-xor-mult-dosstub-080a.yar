rule TTP_XOR_MULT_DOSStub_080a {
  strings:
    $key_080a = { 5c 62 [2] 28 7a [2] 6f 78 [2] 28 69 [2] 66 65 [2] 6a 6f [2] 7d 64 [2] 66 2a [2] 5b }

  condition:
    any of them
}