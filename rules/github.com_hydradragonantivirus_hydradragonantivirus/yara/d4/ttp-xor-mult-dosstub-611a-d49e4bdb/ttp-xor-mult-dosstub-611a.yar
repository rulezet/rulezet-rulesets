rule TTP_XOR_MULT_DOSStub_611a {
  strings:
    $key_611a = { 35 72 [2] 41 6a [2] 06 68 [2] 41 79 [2] 0f 75 [2] 03 7f [2] 14 74 [2] 0f 3a [2] 32 }

  condition:
    any of them
}