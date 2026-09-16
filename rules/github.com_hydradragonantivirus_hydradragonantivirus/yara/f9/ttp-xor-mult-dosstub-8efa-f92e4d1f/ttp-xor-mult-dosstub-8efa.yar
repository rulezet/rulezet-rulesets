rule TTP_XOR_MULT_DOSStub_8efa {
  strings:
    $key_8efa = { da 92 [2] ae 8a [2] e9 88 [2] ae 99 [2] e0 95 [2] ec 9f [2] fb 94 [2] e0 da [2] dd }

  condition:
    any of them
}