rule TTP_XOR_MULT_DOSStub_8e5c {
  strings:
    $key_8e5c = { da 34 [2] ae 2c [2] e9 2e [2] ae 3f [2] e0 33 [2] ec 39 [2] fb 32 [2] e0 7c [2] dd }

  condition:
    any of them
}