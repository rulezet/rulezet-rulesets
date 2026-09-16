rule TTP_XOR_MULT_DOSStub_8e2e {
  strings:
    $key_8e2e = { da 46 [2] ae 5e [2] e9 5c [2] ae 4d [2] e0 41 [2] ec 4b [2] fb 40 [2] e0 0e [2] dd }

  condition:
    any of them
}