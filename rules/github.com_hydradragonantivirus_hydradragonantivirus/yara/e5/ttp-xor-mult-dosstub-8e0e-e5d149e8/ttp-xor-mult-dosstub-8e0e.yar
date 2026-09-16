rule TTP_XOR_MULT_DOSStub_8e0e {
  strings:
    $key_8e0e = { da 66 [2] ae 7e [2] e9 7c [2] ae 6d [2] e0 61 [2] ec 6b [2] fb 60 [2] e0 2e [2] dd }

  condition:
    any of them
}