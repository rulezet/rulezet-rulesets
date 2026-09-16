rule TTP_XOR_MULT_DOSStub_dcd7 {
  strings:
    $key_dcd7 = { 88 bf [2] fc a7 [2] bb a5 [2] fc b4 [2] b2 b8 [2] be b2 [2] a9 b9 [2] b2 f7 [2] 8f }

  condition:
    any of them
}