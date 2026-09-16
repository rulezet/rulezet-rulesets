rule TTP_XOR_MULT_DOSStub_0f39 {
  strings:
    $key_0f39 = { 5b 51 [2] 2f 49 [2] 68 4b [2] 2f 5a [2] 61 56 [2] 6d 5c [2] 7a 57 [2] 61 19 [2] 5c }

  condition:
    any of them
}