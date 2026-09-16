rule TTP_XOR_MULT_DOSStub_8e02 {
  strings:
    $key_8e02 = { da 6a [2] ae 72 [2] e9 70 [2] ae 61 [2] e0 6d [2] ec 67 [2] fb 6c [2] e0 22 [2] dd }

  condition:
    any of them
}