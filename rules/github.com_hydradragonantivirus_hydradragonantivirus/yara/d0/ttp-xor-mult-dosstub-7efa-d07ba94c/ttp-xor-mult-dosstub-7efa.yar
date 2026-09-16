rule TTP_XOR_MULT_DOSStub_7efa {
  strings:
    $key_7efa = { 2a 92 [2] 5e 8a [2] 19 88 [2] 5e 99 [2] 10 95 [2] 1c 9f [2] 0b 94 [2] 10 da [2] 2d }

  condition:
    any of them
}