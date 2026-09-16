rule TTP_XOR_MULT_DOSStub_2705 {
  strings:
    $key_2705 = { 73 6d [2] 07 75 [2] 40 77 [2] 07 66 [2] 49 6a [2] 45 60 [2] 52 6b [2] 49 25 [2] 74 }

  condition:
    any of them
}