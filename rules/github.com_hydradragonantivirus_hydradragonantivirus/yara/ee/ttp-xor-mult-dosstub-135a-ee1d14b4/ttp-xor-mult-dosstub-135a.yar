rule TTP_XOR_MULT_DOSStub_135a {
  strings:
    $key_135a = { 47 32 [2] 33 2a [2] 74 28 [2] 33 39 [2] 7d 35 [2] 71 3f [2] 66 34 [2] 7d 7a [2] 40 }

  condition:
    any of them
}