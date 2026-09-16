rule TTP_XOR_MULT_DOSStub_8e66 {
  strings:
    $key_8e66 = { da 0e [2] ae 16 [2] e9 14 [2] ae 05 [2] e0 09 [2] ec 03 [2] fb 08 [2] e0 46 [2] dd }

  condition:
    any of them
}