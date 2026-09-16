rule TTP_XOR_MULT_DOSStub_7dae {
  strings:
    $key_7dae = { 29 c6 [2] 5d de [2] 1a dc [2] 5d cd [2] 13 c1 [2] 1f cb [2] 08 c0 [2] 13 8e [2] 2e }

  condition:
    any of them
}