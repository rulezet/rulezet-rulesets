rule TTP_XOR_MULT_DOSStub_a8bd {
  strings:
    $key_a8bd = { fc d5 [2] 88 cd [2] cf cf [2] 88 de [2] c6 d2 [2] ca d8 [2] dd d3 [2] c6 9d [2] fb }

  condition:
    any of them
}