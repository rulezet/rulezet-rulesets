rule TTP_XOR_MULT_DOSStub_8e0d {
  strings:
    $key_8e0d = { da 65 [2] ae 7d [2] e9 7f [2] ae 6e [2] e0 62 [2] ec 68 [2] fb 63 [2] e0 2d [2] dd }

  condition:
    any of them
}