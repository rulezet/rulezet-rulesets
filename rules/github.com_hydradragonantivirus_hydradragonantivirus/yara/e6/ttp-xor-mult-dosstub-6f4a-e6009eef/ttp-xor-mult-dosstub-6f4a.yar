rule TTP_XOR_MULT_DOSStub_6f4a {
  strings:
    $key_6f4a = { 3b 22 [2] 4f 3a [2] 08 38 [2] 4f 29 [2] 01 25 [2] 0d 2f [2] 1a 24 [2] 01 6a [2] 3c }

  condition:
    any of them
}