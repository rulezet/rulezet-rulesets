rule TTP_XOR_MULT_DOSStub_8e73 {
  strings:
    $key_8e73 = { da 1b [2] ae 03 [2] e9 01 [2] ae 10 [2] e0 1c [2] ec 16 [2] fb 1d [2] e0 53 [2] dd }

  condition:
    any of them
}