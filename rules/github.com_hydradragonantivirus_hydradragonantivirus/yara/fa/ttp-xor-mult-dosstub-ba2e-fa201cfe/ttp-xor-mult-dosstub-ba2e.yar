rule TTP_XOR_MULT_DOSStub_ba2e {
  strings:
    $key_ba2e = { ee 46 [2] 9a 5e [2] dd 5c [2] 9a 4d [2] d4 41 [2] d8 4b [2] cf 40 [2] d4 0e [2] e9 }

  condition:
    any of them
}