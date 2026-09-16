rule TTP_XOR_MULT_DOSStub_1da8 {
  strings:
    $key_1da8 = { 49 c0 [2] 3d d8 [2] 7a da [2] 3d cb [2] 73 c7 [2] 7f cd [2] 68 c6 [2] 73 88 [2] 4e }

  condition:
    any of them
}