rule TTP_XOR_MULT_DOSStub_ba58 {
  strings:
    $key_ba58 = { ee 30 [2] 9a 28 [2] dd 2a [2] 9a 3b [2] d4 37 [2] d8 3d [2] cf 36 [2] d4 78 [2] e9 }

  condition:
    any of them
}