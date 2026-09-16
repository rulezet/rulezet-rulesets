rule TTP_XOR_MULT_DOSStub_1dcb {
  strings:
    $key_1dcb = { 49 a3 [2] 3d bb [2] 7a b9 [2] 3d a8 [2] 73 a4 [2] 7f ae [2] 68 a5 [2] 73 eb [2] 4e }

  condition:
    any of them
}