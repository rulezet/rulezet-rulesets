rule TTP_XOR_MULT_DOSStub_8e4a {
  strings:
    $key_8e4a = { da 22 [2] ae 3a [2] e9 38 [2] ae 29 [2] e0 25 [2] ec 2f [2] fb 24 [2] e0 6a [2] dd }

  condition:
    any of them
}