rule TTP_XOR_MULT_DOSStub_7cae {
  strings:
    $key_7cae = { 28 c6 [2] 5c de [2] 1b dc [2] 5c cd [2] 12 c1 [2] 1e cb [2] 09 c0 [2] 12 8e [2] 2f }

  condition:
    any of them
}