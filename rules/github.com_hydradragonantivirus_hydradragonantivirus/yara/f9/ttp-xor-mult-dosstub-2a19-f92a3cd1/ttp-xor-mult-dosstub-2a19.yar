rule TTP_XOR_MULT_DOSStub_2a19 {
  strings:
    $key_2a19 = { 7e 71 [2] 0a 69 [2] 4d 6b [2] 0a 7a [2] 44 76 [2] 48 7c [2] 5f 77 [2] 44 39 [2] 79 }

  condition:
    any of them
}