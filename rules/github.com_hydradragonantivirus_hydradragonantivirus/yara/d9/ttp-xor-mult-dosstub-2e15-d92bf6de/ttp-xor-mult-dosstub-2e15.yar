rule TTP_XOR_MULT_DOSStub_2e15 {
  strings:
    $key_2e15 = { 7a 7d [2] 0e 65 [2] 49 67 [2] 0e 76 [2] 40 7a [2] 4c 70 [2] 5b 7b [2] 40 35 [2] 7d }

  condition:
    any of them
}