rule TTP_XOR_MULT_DOSStub_3dae {
  strings:
    $key_3dae = { 69 c6 [2] 1d de [2] 5a dc [2] 1d cd [2] 53 c1 [2] 5f cb [2] 48 c0 [2] 53 8e [2] 6e }

  condition:
    any of them
}