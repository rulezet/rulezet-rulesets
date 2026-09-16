rule TTP_XOR_MULT_DOSStub_281a {
  strings:
    $key_281a = { 7c 72 [2] 08 6a [2] 4f 68 [2] 08 79 [2] 46 75 [2] 4a 7f [2] 5d 74 [2] 46 3a [2] 7b }

  condition:
    any of them
}