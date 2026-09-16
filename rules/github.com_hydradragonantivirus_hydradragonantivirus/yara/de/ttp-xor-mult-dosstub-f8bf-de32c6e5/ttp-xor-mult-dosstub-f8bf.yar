rule TTP_XOR_MULT_DOSStub_f8bf {
  strings:
    $key_f8bf = { ac d7 [2] d8 cf [2] 9f cd [2] d8 dc [2] 96 d0 [2] 9a da [2] 8d d1 [2] 96 9f [2] ab }

  condition:
    any of them
}