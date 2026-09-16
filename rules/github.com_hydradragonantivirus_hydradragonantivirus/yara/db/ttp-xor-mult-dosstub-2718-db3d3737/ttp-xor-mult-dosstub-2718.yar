rule TTP_XOR_MULT_DOSStub_2718 {
  strings:
    $key_2718 = { 73 70 [2] 07 68 [2] 40 6a [2] 07 7b [2] 49 77 [2] 45 7d [2] 52 76 [2] 49 38 [2] 74 }

  condition:
    any of them
}