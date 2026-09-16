rule TTP_XOR_MULT_DOSStub_a8bf {
  strings:
    $key_a8bf = { fc d7 [2] 88 cf [2] cf cd [2] 88 dc [2] c6 d0 [2] ca da [2] dd d1 [2] c6 9f [2] fb }

  condition:
    any of them
}