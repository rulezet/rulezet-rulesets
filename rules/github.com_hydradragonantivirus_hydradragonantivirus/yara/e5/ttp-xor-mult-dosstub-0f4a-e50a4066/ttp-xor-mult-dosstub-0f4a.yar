rule TTP_XOR_MULT_DOSStub_0f4a {
  strings:
    $key_0f4a = { 5b 22 [2] 2f 3a [2] 68 38 [2] 2f 29 [2] 61 25 [2] 6d 2f [2] 7a 24 [2] 61 6a [2] 5c }

  condition:
    any of them
}