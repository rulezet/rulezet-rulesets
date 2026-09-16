rule TTP_XOR_MULT_DOSStub_8e09 {
  strings:
    $key_8e09 = { da 61 [2] ae 79 [2] e9 7b [2] ae 6a [2] e0 66 [2] ec 6c [2] fb 67 [2] e0 29 [2] dd }

  condition:
    any of them
}