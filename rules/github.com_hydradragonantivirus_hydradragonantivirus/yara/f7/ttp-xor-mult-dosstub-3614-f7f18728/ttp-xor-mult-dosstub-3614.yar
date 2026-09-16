rule TTP_XOR_MULT_DOSStub_3614 {
  strings:
    $key_3614 = { 62 7c [2] 16 64 [2] 51 66 [2] 16 77 [2] 58 7b [2] 54 71 [2] 43 7a [2] 58 34 [2] 65 }

  condition:
    any of them
}