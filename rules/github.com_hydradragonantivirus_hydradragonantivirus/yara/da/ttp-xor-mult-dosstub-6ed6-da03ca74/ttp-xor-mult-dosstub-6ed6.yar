rule TTP_XOR_MULT_DOSStub_6ed6 {
  strings:
    $key_6ed6 = { 3a be [2] 4e a6 [2] 09 a4 [2] 4e b5 [2] 00 b9 [2] 0c b3 [2] 1b b8 [2] 00 f6 [2] 3d }

  condition:
    any of them
}