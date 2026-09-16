rule TTP_XOR_MULT_DOSStub_ee75 {
  strings:
    $key_ee75 = { ba 1d [2] ce 05 [2] 89 07 [2] ce 16 [2] 80 1a [2] 8c 10 [2] 9b 1b [2] 80 55 [2] bd }

  condition:
    any of them
}