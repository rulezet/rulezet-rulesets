rule TTP_XOR_MULT_DOSStub_4509 {
  strings:
    $key_4509 = { 11 61 [2] 65 79 [2] 22 7b [2] 65 6a [2] 2b 66 [2] 27 6c [2] 30 67 [2] 2b 29 [2] 16 }

  condition:
    any of them
}