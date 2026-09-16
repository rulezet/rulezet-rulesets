rule TTP_XOR_MULT_DOSStub_484a {
  strings:
    $key_484a = { 1c 22 [2] 68 3a [2] 2f 38 [2] 68 29 [2] 26 25 [2] 2a 2f [2] 3d 24 [2] 26 6a [2] 1b }

  condition:
    any of them
}