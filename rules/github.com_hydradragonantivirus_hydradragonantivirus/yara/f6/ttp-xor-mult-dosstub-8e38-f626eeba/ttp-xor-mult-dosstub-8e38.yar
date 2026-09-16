rule TTP_XOR_MULT_DOSStub_8e38 {
  strings:
    $key_8e38 = { da 50 [2] ae 48 [2] e9 4a [2] ae 5b [2] e0 57 [2] ec 5d [2] fb 56 [2] e0 18 [2] dd }

  condition:
    any of them
}