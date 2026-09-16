rule TTP_XOR_MULT_DOSStub_ba46 {
  strings:
    $key_ba46 = { ee 2e [2] 9a 36 [2] dd 34 [2] 9a 25 [2] d4 29 [2] d8 23 [2] cf 28 [2] d4 66 [2] e9 }

  condition:
    any of them
}