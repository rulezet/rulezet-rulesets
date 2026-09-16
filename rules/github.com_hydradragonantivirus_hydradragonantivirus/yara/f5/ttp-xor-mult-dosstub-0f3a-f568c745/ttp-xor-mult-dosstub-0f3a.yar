rule TTP_XOR_MULT_DOSStub_0f3a {
  strings:
    $key_0f3a = { 5b 52 [2] 2f 4a [2] 68 48 [2] 2f 59 [2] 61 55 [2] 6d 5f [2] 7a 54 [2] 61 1a [2] 5c }

  condition:
    any of them
}