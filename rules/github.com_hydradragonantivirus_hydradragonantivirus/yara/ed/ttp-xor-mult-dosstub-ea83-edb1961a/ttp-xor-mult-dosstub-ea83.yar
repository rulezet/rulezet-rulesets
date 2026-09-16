rule TTP_XOR_MULT_DOSStub_ea83 {
  strings:
    $key_ea83 = { be eb [2] ca f3 [2] 8d f1 [2] ca e0 [2] 84 ec [2] 88 e6 [2] 9f ed [2] 84 a3 [2] b9 }

  condition:
    any of them
}