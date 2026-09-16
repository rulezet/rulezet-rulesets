rule TTP_XOR_MULT_DOSStub_2219 {
  strings:
    $key_2219 = { 76 71 [2] 02 69 [2] 45 6b [2] 02 7a [2] 4c 76 [2] 40 7c [2] 57 77 [2] 4c 39 [2] 71 }

  condition:
    any of them
}