rule TTP_XOR_MULT_DOSStub_eefa {
  strings:
    $key_eefa = { ba 92 [2] ce 8a [2] 89 88 [2] ce 99 [2] 80 95 [2] 8c 9f [2] 9b 94 [2] 80 da [2] bd }

  condition:
    any of them
}