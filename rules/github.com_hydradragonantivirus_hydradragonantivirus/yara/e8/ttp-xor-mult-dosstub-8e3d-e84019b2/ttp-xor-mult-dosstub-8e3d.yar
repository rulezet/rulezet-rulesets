rule TTP_XOR_MULT_DOSStub_8e3d {
  strings:
    $key_8e3d = { da 55 [2] ae 4d [2] e9 4f [2] ae 5e [2] e0 52 [2] ec 58 [2] fb 53 [2] e0 1d [2] dd }

  condition:
    any of them
}