rule TTP_XOR_MULT_DOSStub_ba2a {
  strings:
    $key_ba2a = { ee 42 [2] 9a 5a [2] dd 58 [2] 9a 49 [2] d4 45 [2] d8 4f [2] cf 44 [2] d4 0a [2] e9 }

  condition:
    any of them
}