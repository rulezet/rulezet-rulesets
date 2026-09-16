rule TTP_XOR_MULT_DOSStub_8ee3 {
  strings:
    $key_8ee3 = { da 8b [2] ae 93 [2] e9 91 [2] ae 80 [2] e0 8c [2] ec 86 [2] fb 8d [2] e0 c3 [2] dd }

  condition:
    any of them
}