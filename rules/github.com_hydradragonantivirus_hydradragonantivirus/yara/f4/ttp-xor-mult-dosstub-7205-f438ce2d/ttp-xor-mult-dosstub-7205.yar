rule TTP_XOR_MULT_DOSStub_7205 {
  strings:
    $key_7205 = { 26 6d [2] 52 75 [2] 15 77 [2] 52 66 [2] 1c 6a [2] 10 60 [2] 07 6b [2] 1c 25 [2] 21 }

  condition:
    any of them
}