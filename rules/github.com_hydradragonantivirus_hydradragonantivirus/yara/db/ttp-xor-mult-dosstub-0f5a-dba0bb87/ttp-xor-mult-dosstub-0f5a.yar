rule TTP_XOR_MULT_DOSStub_0f5a {
  strings:
    $key_0f5a = { 5b 32 [2] 2f 2a [2] 68 28 [2] 2f 39 [2] 61 35 [2] 6d 3f [2] 7a 34 [2] 61 7a [2] 5c }

  condition:
    any of them
}