rule TTP_XOR_MULT_DOSStub_8ee6 {
  strings:
    $key_8ee6 = { da 8e [2] ae 96 [2] e9 94 [2] ae 85 [2] e0 89 [2] ec 83 [2] fb 88 [2] e0 c6 [2] dd }

  condition:
    any of them
}