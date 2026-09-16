rule TTP_XOR_MULT_DOSStub_8e23 {
  strings:
    $key_8e23 = { da 4b [2] ae 53 [2] e9 51 [2] ae 40 [2] e0 4c [2] ec 46 [2] fb 4d [2] e0 03 [2] dd }

  condition:
    any of them
}