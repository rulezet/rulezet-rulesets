rule TTP_XOR_MULT_DOSStub_ba6d {
  strings:
    $key_ba6d = { ee 05 [2] 9a 1d [2] dd 1f [2] 9a 0e [2] d4 02 [2] d8 08 [2] cf 03 [2] d4 4d [2] e9 }

  condition:
    any of them
}