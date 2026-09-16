rule TTP_XOR_MULT_DOSStub_0f34 {
  strings:
    $key_0f34 = { 5b 5c [2] 2f 44 [2] 68 46 [2] 2f 57 [2] 61 5b [2] 6d 51 [2] 7a 5a [2] 61 14 [2] 5c }

  condition:
    any of them
}