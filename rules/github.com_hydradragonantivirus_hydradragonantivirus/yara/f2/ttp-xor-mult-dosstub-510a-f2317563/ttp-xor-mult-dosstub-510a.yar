rule TTP_XOR_MULT_DOSStub_510a {
  strings:
    $key_510a = { 05 62 [2] 71 7a [2] 36 78 [2] 71 69 [2] 3f 65 [2] 33 6f [2] 24 64 [2] 3f 2a [2] 02 }

  condition:
    any of them
}