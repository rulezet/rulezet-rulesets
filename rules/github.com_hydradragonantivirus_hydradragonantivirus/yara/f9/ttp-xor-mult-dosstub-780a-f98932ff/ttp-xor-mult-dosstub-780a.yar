rule TTP_XOR_MULT_DOSStub_780a {
  strings:
    $key_780a = { 2c 62 [2] 58 7a [2] 1f 78 [2] 58 69 [2] 16 65 [2] 1a 6f [2] 0d 64 [2] 16 2a [2] 2b }

  condition:
    any of them
}