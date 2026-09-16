rule TTP_XOR_MULT_DOSStub_c3da {
  strings:
    $key_c3da = { 97 b2 [2] e3 aa [2] a4 a8 [2] e3 b9 [2] ad b5 [2] a1 bf [2] b6 b4 [2] ad fa [2] 90 }

  condition:
    any of them
}