rule TTP_XOR_MULT_DOSStub_3cbd {
  strings:
    $key_3cbd = { 68 d5 [2] 1c cd [2] 5b cf [2] 1c de [2] 52 d2 [2] 5e d8 [2] 49 d3 [2] 52 9d [2] 6f }

  condition:
    any of them
}