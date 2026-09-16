rule TTP_XOR_MULT_DOSStub_ba71 {
  strings:
    $key_ba71 = { ee 19 [2] 9a 01 [2] dd 03 [2] 9a 12 [2] d4 1e [2] d8 14 [2] cf 1f [2] d4 51 [2] e9 }

  condition:
    any of them
}