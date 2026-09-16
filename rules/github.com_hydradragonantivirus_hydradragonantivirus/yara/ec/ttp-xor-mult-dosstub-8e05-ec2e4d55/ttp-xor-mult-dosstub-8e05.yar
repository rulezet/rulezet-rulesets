rule TTP_XOR_MULT_DOSStub_8e05 {
  strings:
    $key_8e05 = { da 6d [2] ae 75 [2] e9 77 [2] ae 66 [2] e0 6a [2] ec 60 [2] fb 6b [2] e0 25 [2] dd }

  condition:
    any of them
}