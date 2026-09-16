rule TTP_XOR_MULT_DOSStub_30bd {
  strings:
    $key_30bd = { 64 d5 [2] 10 cd [2] 57 cf [2] 10 de [2] 5e d2 [2] 52 d8 [2] 45 d3 [2] 5e 9d [2] 63 }

  condition:
    any of them
}