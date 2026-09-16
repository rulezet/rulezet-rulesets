rule TTP_XOR_MULT_DOSStub_8e77 {
  strings:
    $key_8e77 = { da 1f [2] ae 07 [2] e9 05 [2] ae 14 [2] e0 18 [2] ec 12 [2] fb 19 [2] e0 57 [2] dd }

  condition:
    any of them
}