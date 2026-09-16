rule TTP_XOR_MULT_DOSStub_8e87 {
  strings:
    $key_8e87 = { da ef [2] ae f7 [2] e9 f5 [2] ae e4 [2] e0 e8 [2] ec e2 [2] fb e9 [2] e0 a7 [2] dd }

  condition:
    any of them
}