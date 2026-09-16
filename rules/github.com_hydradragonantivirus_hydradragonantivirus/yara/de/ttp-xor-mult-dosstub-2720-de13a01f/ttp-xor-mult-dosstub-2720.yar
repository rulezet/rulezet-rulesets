rule TTP_XOR_MULT_DOSStub_2720 {
  strings:
    $key_2720 = { 73 48 [2] 07 50 [2] 40 52 [2] 07 43 [2] 49 4f [2] 45 45 [2] 52 4e [2] 49 00 [2] 74 }

  condition:
    any of them
}