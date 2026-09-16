rule TTP_XOR_MULT_DOSStub_1ad0 {
  strings:
    $key_1ad0 = { 4e b8 [2] 3a a0 [2] 7d a2 [2] 3a b3 [2] 74 bf [2] 78 b5 [2] 6f be [2] 74 f0 [2] 49 }

  condition:
    any of them
}