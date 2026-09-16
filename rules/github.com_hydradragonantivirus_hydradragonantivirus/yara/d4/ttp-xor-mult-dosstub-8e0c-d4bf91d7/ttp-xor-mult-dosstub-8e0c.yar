rule TTP_XOR_MULT_DOSStub_8e0c {
  strings:
    $key_8e0c = { da 64 [2] ae 7c [2] e9 7e [2] ae 6f [2] e0 63 [2] ec 69 [2] fb 62 [2] e0 2c [2] dd }

  condition:
    any of them
}