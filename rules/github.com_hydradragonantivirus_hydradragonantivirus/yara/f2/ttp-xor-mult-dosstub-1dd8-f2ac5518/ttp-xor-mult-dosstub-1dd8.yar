rule TTP_XOR_MULT_DOSStub_1dd8 {
  strings:
    $key_1dd8 = { 49 b0 [2] 3d a8 [2] 7a aa [2] 3d bb [2] 73 b7 [2] 7f bd [2] 68 b6 [2] 73 f8 [2] 4e }

  condition:
    any of them
}