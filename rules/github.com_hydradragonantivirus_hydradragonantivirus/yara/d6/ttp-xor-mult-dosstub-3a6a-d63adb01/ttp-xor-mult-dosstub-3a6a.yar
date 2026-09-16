rule TTP_XOR_MULT_DOSStub_3a6a {
  strings:
    $key_3a6a = { 6e 02 [2] 1a 1a [2] 5d 18 [2] 1a 09 [2] 54 05 [2] 58 0f [2] 4f 04 [2] 54 4a [2] 69 }

  condition:
    any of them
}