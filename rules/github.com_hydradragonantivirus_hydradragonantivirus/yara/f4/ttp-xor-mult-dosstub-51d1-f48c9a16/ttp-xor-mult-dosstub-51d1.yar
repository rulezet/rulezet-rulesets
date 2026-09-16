rule TTP_XOR_MULT_DOSStub_51d1 {
  strings:
    $key_51d1 = { 05 b9 [2] 71 a1 [2] 36 a3 [2] 71 b2 [2] 3f be [2] 33 b4 [2] 24 bf [2] 3f f1 [2] 02 }

  condition:
    any of them
}