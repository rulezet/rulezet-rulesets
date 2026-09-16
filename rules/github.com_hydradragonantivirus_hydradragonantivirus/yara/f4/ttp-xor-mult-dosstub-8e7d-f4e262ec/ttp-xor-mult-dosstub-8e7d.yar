rule TTP_XOR_MULT_DOSStub_8e7d {
  strings:
    $key_8e7d = { da 15 [2] ae 0d [2] e9 0f [2] ae 1e [2] e0 12 [2] ec 18 [2] fb 13 [2] e0 5d [2] dd }

  condition:
    any of them
}