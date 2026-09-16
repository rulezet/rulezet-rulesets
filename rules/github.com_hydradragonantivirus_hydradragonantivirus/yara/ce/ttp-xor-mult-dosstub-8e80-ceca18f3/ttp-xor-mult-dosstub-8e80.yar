rule TTP_XOR_MULT_DOSStub_8e80 {
  strings:
    $key_8e80 = { da e8 [2] ae f0 [2] e9 f2 [2] ae e3 [2] e0 ef [2] ec e5 [2] fb ee [2] e0 a0 [2] dd }

  condition:
    any of them
}