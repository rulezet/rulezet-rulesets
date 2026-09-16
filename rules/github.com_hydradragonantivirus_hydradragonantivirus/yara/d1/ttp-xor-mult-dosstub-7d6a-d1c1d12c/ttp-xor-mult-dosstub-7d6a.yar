rule TTP_XOR_MULT_DOSStub_7d6a {
  strings:
    $key_7d6a = { 29 02 [2] 5d 1a [2] 1a 18 [2] 5d 09 [2] 13 05 [2] 1f 0f [2] 08 04 [2] 13 4a [2] 2e }

  condition:
    any of them
}