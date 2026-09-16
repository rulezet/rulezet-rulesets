rule TTP_XOR_MULT_DOSStub_1e05 {
  strings:
    $key_1e05 = { 4a 6d [2] 3e 75 [2] 79 77 [2] 3e 66 [2] 70 6a [2] 7c 60 [2] 6b 6b [2] 70 25 [2] 4d }

  condition:
    any of them
}