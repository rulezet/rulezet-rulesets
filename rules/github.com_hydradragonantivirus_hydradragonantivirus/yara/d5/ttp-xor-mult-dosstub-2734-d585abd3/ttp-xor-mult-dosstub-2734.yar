rule TTP_XOR_MULT_DOSStub_2734 {
  strings:
    $key_2734 = { 73 5c [2] 07 44 [2] 40 46 [2] 07 57 [2] 49 5b [2] 45 51 [2] 52 5a [2] 49 14 [2] 74 }

  condition:
    any of them
}