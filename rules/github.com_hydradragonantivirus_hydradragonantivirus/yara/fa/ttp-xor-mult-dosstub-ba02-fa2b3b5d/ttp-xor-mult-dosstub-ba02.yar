rule TTP_XOR_MULT_DOSStub_ba02 {
  strings:
    $key_ba02 = { ee 6a [2] 9a 72 [2] dd 70 [2] 9a 61 [2] d4 6d [2] d8 67 [2] cf 6c [2] d4 22 [2] e9 }

  condition:
    any of them
}