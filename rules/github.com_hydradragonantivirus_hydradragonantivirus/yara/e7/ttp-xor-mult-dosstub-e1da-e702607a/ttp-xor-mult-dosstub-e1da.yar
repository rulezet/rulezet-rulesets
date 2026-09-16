rule TTP_XOR_MULT_DOSStub_e1da {
  strings:
    $key_e1da = { b5 b2 [2] c1 aa [2] 86 a8 [2] c1 b9 [2] 8f b5 [2] 83 bf [2] 94 b4 [2] 8f fa [2] b2 }

  condition:
    any of them
}