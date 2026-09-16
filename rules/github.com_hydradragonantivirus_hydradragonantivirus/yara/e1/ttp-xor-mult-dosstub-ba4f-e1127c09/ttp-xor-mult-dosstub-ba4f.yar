rule TTP_XOR_MULT_DOSStub_ba4f {
  strings:
    $key_ba4f = { ee 27 [2] 9a 3f [2] dd 3d [2] 9a 2c [2] d4 20 [2] d8 2a [2] cf 21 [2] d4 6f [2] e9 }

  condition:
    any of them
}