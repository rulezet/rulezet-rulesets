rule TTP_XOR_MULT_DOSStub_8e89 {
  strings:
    $key_8e89 = { da e1 [2] ae f9 [2] e9 fb [2] ae ea [2] e0 e6 [2] ec ec [2] fb e7 [2] e0 a9 [2] dd }

  condition:
    any of them
}