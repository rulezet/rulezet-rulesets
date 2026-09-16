rule TTP_XOR_MULT_DOSStub_614a {
  strings:
    $key_614a = { 35 22 [2] 41 3a [2] 06 38 [2] 41 29 [2] 0f 25 [2] 03 2f [2] 14 24 [2] 0f 6a [2] 32 }

  condition:
    any of them
}