rule TTP_XOR_MULT_DOSStub_476a {
  strings:
    $key_476a = { 13 02 [2] 67 1a [2] 20 18 [2] 67 09 [2] 29 05 [2] 25 0f [2] 32 04 [2] 29 4a [2] 14 }

  condition:
    any of them
}