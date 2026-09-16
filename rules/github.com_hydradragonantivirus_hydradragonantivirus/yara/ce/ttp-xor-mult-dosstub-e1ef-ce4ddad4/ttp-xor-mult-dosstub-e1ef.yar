rule TTP_XOR_MULT_DOSStub_e1ef {
  strings:
    $key_e1ef = { b5 87 [2] c1 9f [2] 86 9d [2] c1 8c [2] 8f 80 [2] 83 8a [2] 94 81 [2] 8f cf [2] b2 }

  condition:
    any of them
}