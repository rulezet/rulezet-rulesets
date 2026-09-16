rule TTP_XOR_MULT_DOSStub_5d6a {
  strings:
    $key_5d6a = { 09 02 [2] 7d 1a [2] 3a 18 [2] 7d 09 [2] 33 05 [2] 3f 0f [2] 28 04 [2] 33 4a [2] 0e }

  condition:
    any of them
}