rule TTP_XOR_MULT_DOSStub_d7da {
  strings:
    $key_d7da = { 83 b2 [2] f7 aa [2] b0 a8 [2] f7 b9 [2] b9 b5 [2] b5 bf [2] a2 b4 [2] b9 fa [2] 84 }

  condition:
    any of them
}