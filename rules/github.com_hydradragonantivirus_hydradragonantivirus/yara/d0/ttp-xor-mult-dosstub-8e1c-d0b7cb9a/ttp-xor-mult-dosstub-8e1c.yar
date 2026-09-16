rule TTP_XOR_MULT_DOSStub_8e1c {
  strings:
    $key_8e1c = { da 74 [2] ae 6c [2] e9 6e [2] ae 7f [2] e0 73 [2] ec 79 [2] fb 72 [2] e0 3c [2] dd }

  condition:
    any of them
}