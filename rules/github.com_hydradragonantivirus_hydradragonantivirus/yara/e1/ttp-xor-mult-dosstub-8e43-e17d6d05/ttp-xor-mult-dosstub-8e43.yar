rule TTP_XOR_MULT_DOSStub_8e43 {
  strings:
    $key_8e43 = { da 2b [2] ae 33 [2] e9 31 [2] ae 20 [2] e0 2c [2] ec 26 [2] fb 2d [2] e0 63 [2] dd }

  condition:
    any of them
}