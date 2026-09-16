rule TTP_XOR_MULT_DOSStub_6a1a {
  strings:
    $key_6a1a = { 3e 72 [2] 4a 6a [2] 0d 68 [2] 4a 79 [2] 04 75 [2] 08 7f [2] 1f 74 [2] 04 3a [2] 39 }

  condition:
    any of them
}