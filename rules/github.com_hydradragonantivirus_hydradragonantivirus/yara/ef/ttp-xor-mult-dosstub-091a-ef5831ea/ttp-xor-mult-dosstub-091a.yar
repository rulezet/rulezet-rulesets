rule TTP_XOR_MULT_DOSStub_091a {
  strings:
    $key_091a = { 5d 72 [2] 29 6a [2] 6e 68 [2] 29 79 [2] 67 75 [2] 6b 7f [2] 7c 74 [2] 67 3a [2] 5a }

  condition:
    any of them
}