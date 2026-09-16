rule TTP_XOR_MULT_DOSStub_8e84 {
  strings:
    $key_8e84 = { da ec [2] ae f4 [2] e9 f6 [2] ae e7 [2] e0 eb [2] ec e1 [2] fb ea [2] e0 a4 [2] dd }

  condition:
    any of them
}