rule TTP_XOR_MULT_DOSStub_8e24 {
  strings:
    $key_8e24 = { da 4c [2] ae 54 [2] e9 56 [2] ae 47 [2] e0 4b [2] ec 41 [2] fb 4a [2] e0 04 [2] dd }

  condition:
    any of them
}