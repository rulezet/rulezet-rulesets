rule TTP_XOR_MULT_DOSStub_2214 {
  strings:
    $key_2214 = { 76 7c [2] 02 64 [2] 45 66 [2] 02 77 [2] 4c 7b [2] 40 71 [2] 57 7a [2] 4c 34 [2] 71 }

  condition:
    any of them
}