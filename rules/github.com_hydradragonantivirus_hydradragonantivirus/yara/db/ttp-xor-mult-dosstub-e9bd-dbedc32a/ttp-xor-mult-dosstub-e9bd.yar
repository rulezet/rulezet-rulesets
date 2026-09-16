rule TTP_XOR_MULT_DOSStub_e9bd {
  strings:
    $key_e9bd = { bd d5 [2] c9 cd [2] 8e cf [2] c9 de [2] 87 d2 [2] 8b d8 [2] 9c d3 [2] 87 9d [2] ba }

  condition:
    any of them
}