rule TTP_XOR_MULT_DOSStub_8e17 {
  strings:
    $key_8e17 = { da 7f [2] ae 67 [2] e9 65 [2] ae 74 [2] e0 78 [2] ec 72 [2] fb 79 [2] e0 37 [2] dd }

  condition:
    any of them
}