rule TTP_XOR_MULT_DOSStub_7b05 {
  strings:
    $key_7b05 = { 2f 6d [2] 5b 75 [2] 1c 77 [2] 5b 66 [2] 15 6a [2] 19 60 [2] 0e 6b [2] 15 25 [2] 28 }

  condition:
    any of them
}