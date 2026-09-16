rule TTP_XOR_MULT_DOSStub_5cae {
  strings:
    $key_5cae = { 08 c6 [2] 7c de [2] 3b dc [2] 7c cd [2] 32 c1 [2] 3e cb [2] 29 c0 [2] 32 8e [2] 0f }

  condition:
    any of them
}