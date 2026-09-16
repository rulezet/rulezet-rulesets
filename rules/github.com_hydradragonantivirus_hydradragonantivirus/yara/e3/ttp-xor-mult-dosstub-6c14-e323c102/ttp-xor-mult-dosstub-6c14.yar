rule TTP_XOR_MULT_DOSStub_6c14 {
  strings:
    $key_6c14 = { 38 7c [2] 4c 64 [2] 0b 66 [2] 4c 77 [2] 02 7b [2] 0e 71 [2] 19 7a [2] 02 34 [2] 3f }

  condition:
    any of them
}