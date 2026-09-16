rule TTP_XOR_MULT_DOSStub_2730 {
  strings:
    $key_2730 = { 73 58 [2] 07 40 [2] 40 42 [2] 07 53 [2] 49 5f [2] 45 55 [2] 52 5e [2] 49 10 [2] 74 }

  condition:
    any of them
}