rule TTP_XOR_MULT_DOSStub_8e4c {
  strings:
    $key_8e4c = { da 24 [2] ae 3c [2] e9 3e [2] ae 2f [2] e0 23 [2] ec 29 [2] fb 22 [2] e0 6c [2] dd }

  condition:
    any of them
}