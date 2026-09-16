rule TTP_XOR_MULT_DOSStub_1d8d {
  strings:
    $key_1d8d = { 49 e5 [2] 3d fd [2] 7a ff [2] 3d ee [2] 73 e2 [2] 7f e8 [2] 68 e3 [2] 73 ad [2] 4e }

  condition:
    any of them
}