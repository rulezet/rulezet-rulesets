rule TTP_XOR_MULT_DOSStub_6cbd {
  strings:
    $key_6cbd = { 38 d5 [2] 4c cd [2] 0b cf [2] 4c de [2] 02 d2 [2] 0e d8 [2] 19 d3 [2] 02 9d [2] 3f }

  condition:
    any of them
}