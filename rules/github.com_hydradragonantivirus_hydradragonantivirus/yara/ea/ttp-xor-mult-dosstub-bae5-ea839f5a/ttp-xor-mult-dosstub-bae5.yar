rule TTP_XOR_MULT_DOSStub_bae5 {
  strings:
    $key_bae5 = { ee 8d [2] 9a 95 [2] dd 97 [2] 9a 86 [2] d4 8a [2] d8 80 [2] cf 8b [2] d4 c5 [2] e9 }

  condition:
    any of them
}