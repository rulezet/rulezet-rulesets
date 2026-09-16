rule TTP_XOR_MULT_DOSStub_0f75 {
  strings:
    $key_0f75 = { 5b 1d [2] 2f 05 [2] 68 07 [2] 2f 16 [2] 61 1a [2] 6d 10 [2] 7a 1b [2] 61 55 [2] 5c }

  condition:
    any of them
}