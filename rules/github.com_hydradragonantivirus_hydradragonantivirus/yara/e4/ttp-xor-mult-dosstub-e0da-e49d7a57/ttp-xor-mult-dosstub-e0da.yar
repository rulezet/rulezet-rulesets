rule TTP_XOR_MULT_DOSStub_e0da {
  strings:
    $key_e0da = { b4 b2 [2] c0 aa [2] 87 a8 [2] c0 b9 [2] 8e b5 [2] 82 bf [2] 95 b4 [2] 8e fa [2] b3 }

  condition:
    any of them
}