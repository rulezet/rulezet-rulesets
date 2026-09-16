rule TTP_XOR_MULT_DOSStub_3efa {
  strings:
    $key_3efa = { 6a 92 [2] 1e 8a [2] 59 88 [2] 1e 99 [2] 50 95 [2] 5c 9f [2] 4b 94 [2] 50 da [2] 6d }

  condition:
    any of them
}