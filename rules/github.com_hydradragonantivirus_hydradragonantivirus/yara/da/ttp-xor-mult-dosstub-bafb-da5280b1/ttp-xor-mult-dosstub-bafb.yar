rule TTP_XOR_MULT_DOSStub_bafb {
  strings:
    $key_bafb = { ee 93 [2] 9a 8b [2] dd 89 [2] 9a 98 [2] d4 94 [2] d8 9e [2] cf 95 [2] d4 db [2] e9 }

  condition:
    any of them
}