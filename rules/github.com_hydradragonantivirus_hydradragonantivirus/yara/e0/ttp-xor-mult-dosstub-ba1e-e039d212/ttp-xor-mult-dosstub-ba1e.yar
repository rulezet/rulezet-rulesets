rule TTP_XOR_MULT_DOSStub_ba1e {
  strings:
    $key_ba1e = { ee 76 [2] 9a 6e [2] dd 6c [2] 9a 7d [2] d4 71 [2] d8 7b [2] cf 70 [2] d4 3e [2] e9 }

  condition:
    any of them
}