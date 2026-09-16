rule TTP_XOR_MULT_DOSStub_2f14 {
  strings:
    $key_2f14 = { 7b 7c [2] 0f 64 [2] 48 66 [2] 0f 77 [2] 41 7b [2] 4d 71 [2] 5a 7a [2] 41 34 [2] 7c }

  condition:
    any of them
}