rule TTP_XOR_MULT_DOSStub_8e5b {
  strings:
    $key_8e5b = { da 33 [2] ae 2b [2] e9 29 [2] ae 38 [2] e0 34 [2] ec 3e [2] fb 35 [2] e0 7b [2] dd }

  condition:
    any of them
}