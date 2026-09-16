rule TTP_XOR_MULT_DOSStub_8e1a {
  strings:
    $key_8e1a = { da 72 [2] ae 6a [2] e9 68 [2] ae 79 [2] e0 75 [2] ec 7f [2] fb 74 [2] e0 3a [2] dd }

  condition:
    any of them
}