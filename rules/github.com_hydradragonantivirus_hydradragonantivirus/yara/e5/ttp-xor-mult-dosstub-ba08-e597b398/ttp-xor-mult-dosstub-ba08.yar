rule TTP_XOR_MULT_DOSStub_ba08 {
  strings:
    $key_ba08 = { ee 60 [2] 9a 78 [2] dd 7a [2] 9a 6b [2] d4 67 [2] d8 6d [2] cf 66 [2] d4 28 [2] e9 }

  condition:
    any of them
}