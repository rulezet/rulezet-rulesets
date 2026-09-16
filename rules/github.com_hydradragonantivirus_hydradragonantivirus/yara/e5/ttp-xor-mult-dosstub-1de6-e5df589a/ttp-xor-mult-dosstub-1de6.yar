rule TTP_XOR_MULT_DOSStub_1de6 {
  strings:
    $key_1de6 = { 49 8e [2] 3d 96 [2] 7a 94 [2] 3d 85 [2] 73 89 [2] 7f 83 [2] 68 88 [2] 73 c6 [2] 4e }

  condition:
    any of them
}