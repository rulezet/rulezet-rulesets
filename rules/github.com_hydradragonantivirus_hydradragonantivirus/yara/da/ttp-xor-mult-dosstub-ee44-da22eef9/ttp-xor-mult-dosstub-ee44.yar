rule TTP_XOR_MULT_DOSStub_ee44 {
  strings:
    $key_ee44 = { ba 2c [2] ce 34 [2] 89 36 [2] ce 27 [2] 80 2b [2] 8c 21 [2] 9b 2a [2] 80 64 [2] bd }

  condition:
    any of them
}