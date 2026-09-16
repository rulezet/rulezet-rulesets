rule TTP_XOR_MULT_DOSStub_3f19 {
  strings:
    $key_3f19 = { 6b 71 [2] 1f 69 [2] 58 6b [2] 1f 7a [2] 51 76 [2] 5d 7c [2] 4a 77 [2] 51 39 [2] 6c }

  condition:
    any of them
}