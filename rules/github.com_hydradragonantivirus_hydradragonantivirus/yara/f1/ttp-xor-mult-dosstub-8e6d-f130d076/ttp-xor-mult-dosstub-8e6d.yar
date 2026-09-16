rule TTP_XOR_MULT_DOSStub_8e6d {
  strings:
    $key_8e6d = { da 05 [2] ae 1d [2] e9 1f [2] ae 0e [2] e0 02 [2] ec 08 [2] fb 03 [2] e0 4d [2] dd }

  condition:
    any of them
}