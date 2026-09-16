rule TTP_XOR_MULT_DOSStub_ee40 {
  strings:
    $key_ee40 = { ba 28 [2] ce 30 [2] 89 32 [2] ce 23 [2] 80 2f [2] 8c 25 [2] 9b 2e [2] 80 60 [2] bd }

  condition:
    any of them
}