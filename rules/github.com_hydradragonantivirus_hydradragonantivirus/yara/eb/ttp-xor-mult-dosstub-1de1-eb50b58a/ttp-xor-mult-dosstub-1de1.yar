rule TTP_XOR_MULT_DOSStub_1de1 {
  strings:
    $key_1de1 = { 49 89 [2] 3d 91 [2] 7a 93 [2] 3d 82 [2] 73 8e [2] 7f 84 [2] 68 8f [2] 73 c1 [2] 4e }

  condition:
    any of them
}