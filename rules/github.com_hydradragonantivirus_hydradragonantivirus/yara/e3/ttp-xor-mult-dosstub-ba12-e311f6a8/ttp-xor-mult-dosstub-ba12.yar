rule TTP_XOR_MULT_DOSStub_ba12 {
  strings:
    $key_ba12 = { ee 7a [2] 9a 62 [2] dd 60 [2] 9a 71 [2] d4 7d [2] d8 77 [2] cf 7c [2] d4 32 [2] e9 }

  condition:
    any of them
}