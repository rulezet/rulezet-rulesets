rule TTP_XOR_MULT_DOSStub_8e06 {
  strings:
    $key_8e06 = { da 6e [2] ae 76 [2] e9 74 [2] ae 65 [2] e0 69 [2] ec 63 [2] fb 68 [2] e0 26 [2] dd }

  condition:
    any of them
}