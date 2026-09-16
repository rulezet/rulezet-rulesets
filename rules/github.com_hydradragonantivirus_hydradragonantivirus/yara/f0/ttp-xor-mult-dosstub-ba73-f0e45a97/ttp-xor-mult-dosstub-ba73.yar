rule TTP_XOR_MULT_DOSStub_ba73 {
  strings:
    $key_ba73 = { ee 1b [2] 9a 03 [2] dd 01 [2] 9a 10 [2] d4 1c [2] d8 16 [2] cf 1d [2] d4 53 [2] e9 }

  condition:
    any of them
}