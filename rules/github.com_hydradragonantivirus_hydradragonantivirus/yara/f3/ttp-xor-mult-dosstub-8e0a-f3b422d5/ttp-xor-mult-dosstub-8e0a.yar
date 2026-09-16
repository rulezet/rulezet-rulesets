rule TTP_XOR_MULT_DOSStub_8e0a {
  strings:
    $key_8e0a = { da 62 [2] ae 7a [2] e9 78 [2] ae 69 [2] e0 65 [2] ec 6f [2] fb 64 [2] e0 2a [2] dd }

  condition:
    any of them
}