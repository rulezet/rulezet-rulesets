rule TTP_XOR_MULT_DOSStub_8ee8 {
  strings:
    $key_8ee8 = { da 80 [2] ae 98 [2] e9 9a [2] ae 8b [2] e0 87 [2] ec 8d [2] fb 86 [2] e0 c8 [2] dd }

  condition:
    any of them
}