rule TTP_XOR_MULT_DOSStub_2709 {
  strings:
    $key_2709 = { 73 61 [2] 07 79 [2] 40 7b [2] 07 6a [2] 49 66 [2] 45 6c [2] 52 67 [2] 49 29 [2] 74 }

  condition:
    any of them
}