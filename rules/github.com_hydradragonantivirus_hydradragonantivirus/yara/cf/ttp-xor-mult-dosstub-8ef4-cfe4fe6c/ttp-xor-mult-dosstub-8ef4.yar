rule TTP_XOR_MULT_DOSStub_8ef4 {
  strings:
    $key_8ef4 = { da 9c [2] ae 84 [2] e9 86 [2] ae 97 [2] e0 9b [2] ec 91 [2] fb 9a [2] e0 d4 [2] dd }

  condition:
    any of them
}