rule TTP_XOR_MULT_DOSStub_5a3a {
  strings:
    $key_5a3a = { 0e 52 [2] 7a 4a [2] 3d 48 [2] 7a 59 [2] 34 55 [2] 38 5f [2] 2f 54 [2] 34 1a [2] 09 }

  condition:
    any of them
}