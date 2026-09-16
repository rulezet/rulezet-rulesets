rule TTP_XOR_MULT_DOSStub_6f19 {
  strings:
    $key_6f19 = { 3b 71 [2] 4f 69 [2] 08 6b [2] 4f 7a [2] 01 76 [2] 0d 7c [2] 1a 77 [2] 01 39 [2] 3c }

  condition:
    any of them
}