rule TTP_XOR_MULT_DOSStub_5b14 {
  strings:
    $key_5b14 = { 0f 7c [2] 7b 64 [2] 3c 66 [2] 7b 77 [2] 35 7b [2] 39 71 [2] 2e 7a [2] 35 34 [2] 08 }

  condition:
    any of them
}