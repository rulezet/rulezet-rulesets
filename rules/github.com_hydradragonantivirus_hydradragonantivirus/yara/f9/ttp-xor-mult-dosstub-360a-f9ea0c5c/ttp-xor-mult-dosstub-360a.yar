rule TTP_XOR_MULT_DOSStub_360a {
  strings:
    $key_360a = { 62 62 [2] 16 7a [2] 51 78 [2] 16 69 [2] 58 65 [2] 54 6f [2] 43 64 [2] 58 2a [2] 65 }

  condition:
    any of them
}