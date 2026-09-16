rule TTP_XOR_MULT_DOSStub_ba38 {
  strings:
    $key_ba38 = { ee 50 [2] 9a 48 [2] dd 4a [2] 9a 5b [2] d4 57 [2] d8 5d [2] cf 56 [2] d4 18 [2] e9 }

  condition:
    any of them
}