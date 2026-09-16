rule TTP_XOR_MULT_DOSStub_8e79 {
  strings:
    $key_8e79 = { da 11 [2] ae 09 [2] e9 0b [2] ae 1a [2] e0 16 [2] ec 1c [2] fb 17 [2] e0 59 [2] dd }

  condition:
    any of them
}