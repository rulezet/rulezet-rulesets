rule TTP_XOR_MULT_DOSStub_8e3f {
  strings:
    $key_8e3f = { da 57 [2] ae 4f [2] e9 4d [2] ae 5c [2] e0 50 [2] ec 5a [2] fb 51 [2] e0 1f [2] dd }

  condition:
    any of them
}