rule TTP_XOR_MULT_DOSStub_6ed1 {
  strings:
    $key_6ed1 = { 3a b9 [2] 4e a1 [2] 09 a3 [2] 4e b2 [2] 00 be [2] 0c b4 [2] 1b bf [2] 00 f1 [2] 3d }

  condition:
    any of them
}