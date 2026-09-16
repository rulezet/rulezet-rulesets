rule TTP_XOR_MULT_DOSStub_0f48 {
  strings:
    $key_0f48 = { 5b 20 [2] 2f 38 [2] 68 3a [2] 2f 2b [2] 61 27 [2] 6d 2d [2] 7a 26 [2] 61 68 [2] 5c }

  condition:
    any of them
}