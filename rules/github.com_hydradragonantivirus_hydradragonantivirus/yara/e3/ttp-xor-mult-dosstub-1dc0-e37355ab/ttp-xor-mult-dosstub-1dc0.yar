rule TTP_XOR_MULT_DOSStub_1dc0 {
  strings:
    $key_1dc0 = { 49 a8 [2] 3d b0 [2] 7a b2 [2] 3d a3 [2] 73 af [2] 7f a5 [2] 68 ae [2] 73 e0 [2] 4e }

  condition:
    any of them
}