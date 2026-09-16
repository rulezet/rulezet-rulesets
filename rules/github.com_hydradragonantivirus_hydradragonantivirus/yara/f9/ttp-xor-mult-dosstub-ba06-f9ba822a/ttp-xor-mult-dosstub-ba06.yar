rule TTP_XOR_MULT_DOSStub_ba06 {
  strings:
    $key_ba06 = { ee 6e [2] 9a 76 [2] dd 74 [2] 9a 65 [2] d4 69 [2] d8 63 [2] cf 68 [2] d4 26 [2] e9 }

  condition:
    any of them
}