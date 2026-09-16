rule TTP_XOR_MULT_DOSStub_8e1d {
  strings:
    $key_8e1d = { da 75 [2] ae 6d [2] e9 6f [2] ae 7e [2] e0 72 [2] ec 78 [2] fb 73 [2] e0 3d [2] dd }

  condition:
    any of them
}