rule TTP_XOR_MULT_DOSStub_2741 {
  strings:
    $key_2741 = { 73 29 [2] 07 31 [2] 40 33 [2] 07 22 [2] 49 2e [2] 45 24 [2] 52 2f [2] 49 61 [2] 74 }

  condition:
    any of them
}