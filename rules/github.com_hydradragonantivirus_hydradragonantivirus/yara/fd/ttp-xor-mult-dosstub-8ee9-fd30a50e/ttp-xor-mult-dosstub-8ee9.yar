rule TTP_XOR_MULT_DOSStub_8ee9 {
  strings:
    $key_8ee9 = { da 81 [2] ae 99 [2] e9 9b [2] ae 8a [2] e0 86 [2] ec 8c [2] fb 87 [2] e0 c9 [2] dd }

  condition:
    any of them
}