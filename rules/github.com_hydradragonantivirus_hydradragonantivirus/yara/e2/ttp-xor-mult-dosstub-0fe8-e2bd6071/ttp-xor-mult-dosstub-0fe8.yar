rule TTP_XOR_MULT_DOSStub_0fe8 {
  strings:
    $key_0fe8 = { 5b 80 [2] 2f 98 [2] 68 9a [2] 2f 8b [2] 61 87 [2] 6d 8d [2] 7a 86 [2] 61 c8 [2] 5c }

  condition:
    any of them
}