rule TTP_XOR_MULT_DOSStub_1dc6 {
  strings:
    $key_1dc6 = { 49 ae [2] 3d b6 [2] 7a b4 [2] 3d a5 [2] 73 a9 [2] 7f a3 [2] 68 a8 [2] 73 e6 [2] 4e }

  condition:
    any of them
}