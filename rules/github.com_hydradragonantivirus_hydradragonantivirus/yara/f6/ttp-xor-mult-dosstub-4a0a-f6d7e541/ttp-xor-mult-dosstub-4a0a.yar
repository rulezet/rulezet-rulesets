rule TTP_XOR_MULT_DOSStub_4a0a {
  strings:
    $key_4a0a = { 1e 62 [2] 6a 7a [2] 2d 78 [2] 6a 69 [2] 24 65 [2] 28 6f [2] 3f 64 [2] 24 2a [2] 19 }

  condition:
    any of them
}