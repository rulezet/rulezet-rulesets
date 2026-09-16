rule TTP_XOR_MULT_DOSStub_361a {
  strings:
    $key_361a = { 62 72 [2] 16 6a [2] 51 68 [2] 16 79 [2] 58 75 [2] 54 7f [2] 43 74 [2] 58 3a [2] 65 }

  condition:
    any of them
}