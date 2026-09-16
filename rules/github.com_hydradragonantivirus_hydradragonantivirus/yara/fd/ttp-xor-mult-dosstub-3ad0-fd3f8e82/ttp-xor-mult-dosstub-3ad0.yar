rule TTP_XOR_MULT_DOSStub_3ad0 {
  strings:
    $key_3ad0 = { 6e b8 [2] 1a a0 [2] 5d a2 [2] 1a b3 [2] 54 bf [2] 58 b5 [2] 4f be [2] 54 f0 [2] 69 }

  condition:
    any of them
}