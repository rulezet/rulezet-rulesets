rule TTP_XOR_MULT_DOSStub_2514 {
  strings:
    $key_2514 = { 71 7c [2] 05 64 [2] 42 66 [2] 05 77 [2] 4b 7b [2] 47 71 [2] 50 7a [2] 4b 34 [2] 76 }

  condition:
    any of them
}