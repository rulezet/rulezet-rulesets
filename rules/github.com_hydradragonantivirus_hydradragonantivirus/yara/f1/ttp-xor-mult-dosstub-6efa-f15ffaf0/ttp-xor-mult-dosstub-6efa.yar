rule TTP_XOR_MULT_DOSStub_6efa {
  strings:
    $key_6efa = { 3a 92 [2] 4e 8a [2] 09 88 [2] 4e 99 [2] 00 95 [2] 0c 9f [2] 1b 94 [2] 00 da [2] 3d }

  condition:
    any of them
}