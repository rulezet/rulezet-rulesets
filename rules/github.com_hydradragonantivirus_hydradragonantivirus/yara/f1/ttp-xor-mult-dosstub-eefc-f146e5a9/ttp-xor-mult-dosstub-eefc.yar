rule TTP_XOR_MULT_DOSStub_eefc {
  strings:
    $key_eefc = { ba 94 [2] ce 8c [2] 89 8e [2] ce 9f [2] 80 93 [2] 8c 99 [2] 9b 92 [2] 80 dc [2] bd }

  condition:
    any of them
}