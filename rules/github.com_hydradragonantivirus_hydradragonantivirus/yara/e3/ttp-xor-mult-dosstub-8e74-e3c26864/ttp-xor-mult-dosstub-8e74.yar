rule TTP_XOR_MULT_DOSStub_8e74 {
  strings:
    $key_8e74 = { da 1c [2] ae 04 [2] e9 06 [2] ae 17 [2] e0 1b [2] ec 11 [2] fb 1a [2] e0 54 [2] dd }

  condition:
    any of them
}