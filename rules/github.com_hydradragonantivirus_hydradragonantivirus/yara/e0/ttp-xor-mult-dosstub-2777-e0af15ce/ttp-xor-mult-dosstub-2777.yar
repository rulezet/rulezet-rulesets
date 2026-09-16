rule TTP_XOR_MULT_DOSStub_2777 {
  strings:
    $key_2777 = { 73 1f [2] 07 07 [2] 40 05 [2] 07 14 [2] 49 18 [2] 45 12 [2] 52 19 [2] 49 57 [2] 74 }

  condition:
    any of them
}