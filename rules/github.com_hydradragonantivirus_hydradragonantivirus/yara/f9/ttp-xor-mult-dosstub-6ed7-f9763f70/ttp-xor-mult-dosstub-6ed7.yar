rule TTP_XOR_MULT_DOSStub_6ed7 {
  strings:
    $key_6ed7 = { 3a bf [2] 4e a7 [2] 09 a5 [2] 4e b4 [2] 00 b8 [2] 0c b2 [2] 1b b9 [2] 00 f7 [2] 3d }

  condition:
    any of them
}