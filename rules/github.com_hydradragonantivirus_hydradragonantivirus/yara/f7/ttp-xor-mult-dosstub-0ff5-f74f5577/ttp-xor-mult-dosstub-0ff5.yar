rule TTP_XOR_MULT_DOSStub_0ff5 {
  strings:
    $key_0ff5 = { 5b 9d [2] 2f 85 [2] 68 87 [2] 2f 96 [2] 61 9a [2] 6d 90 [2] 7a 9b [2] 61 d5 [2] 5c }

  condition:
    any of them
}