rule TTP_XOR_MULT_DOSStub_ba40 {
  strings:
    $key_ba40 = { ee 28 [2] 9a 30 [2] dd 32 [2] 9a 23 [2] d4 2f [2] d8 25 [2] cf 2e [2] d4 60 [2] e9 }

  condition:
    any of them
}