rule TTP_XOR_MULT_DOSStub_ba0e {
  strings:
    $key_ba0e = { ee 66 [2] 9a 7e [2] dd 7c [2] 9a 6d [2] d4 61 [2] d8 6b [2] cf 60 [2] d4 2e [2] e9 }

  condition:
    any of them
}