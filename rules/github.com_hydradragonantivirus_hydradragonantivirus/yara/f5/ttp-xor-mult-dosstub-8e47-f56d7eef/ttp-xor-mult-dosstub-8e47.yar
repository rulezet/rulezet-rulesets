rule TTP_XOR_MULT_DOSStub_8e47 {
  strings:
    $key_8e47 = { da 2f [2] ae 37 [2] e9 35 [2] ae 24 [2] e0 28 [2] ec 22 [2] fb 29 [2] e0 67 [2] dd }

  condition:
    any of them
}