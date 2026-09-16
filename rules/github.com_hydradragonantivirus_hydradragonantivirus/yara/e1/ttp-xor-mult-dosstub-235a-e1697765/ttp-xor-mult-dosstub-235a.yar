rule TTP_XOR_MULT_DOSStub_235a {
  strings:
    $key_235a = { 77 32 [2] 03 2a [2] 44 28 [2] 03 39 [2] 4d 35 [2] 41 3f [2] 56 34 [2] 4d 7a [2] 70 }

  condition:
    any of them
}