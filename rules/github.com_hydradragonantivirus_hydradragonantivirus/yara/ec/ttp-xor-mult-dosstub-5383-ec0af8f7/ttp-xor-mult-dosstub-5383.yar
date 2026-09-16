rule TTP_XOR_MULT_DOSStub_5383 {
  strings:
    $key_5383 = { 07 eb [2] 73 f3 [2] 34 f1 [2] 73 e0 [2] 3d ec [2] 31 e6 [2] 26 ed [2] 3d a3 [2] 00 }

  condition:
    any of them
}