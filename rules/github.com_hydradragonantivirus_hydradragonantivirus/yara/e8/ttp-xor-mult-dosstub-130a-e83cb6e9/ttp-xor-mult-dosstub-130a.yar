rule TTP_XOR_MULT_DOSStub_130a {
  strings:
    $key_130a = { 47 62 [2] 33 7a [2] 74 78 [2] 33 69 [2] 7d 65 [2] 71 6f [2] 66 64 [2] 7d 2a [2] 40 }

  condition:
    any of them
}