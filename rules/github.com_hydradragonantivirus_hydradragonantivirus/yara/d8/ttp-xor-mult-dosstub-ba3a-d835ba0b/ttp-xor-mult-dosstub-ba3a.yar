rule TTP_XOR_MULT_DOSStub_ba3a {
  strings:
    $key_ba3a = { ee 52 [2] 9a 4a [2] dd 48 [2] 9a 59 [2] d4 55 [2] d8 5f [2] cf 54 [2] d4 1a [2] e9 }

  condition:
    any of them
}