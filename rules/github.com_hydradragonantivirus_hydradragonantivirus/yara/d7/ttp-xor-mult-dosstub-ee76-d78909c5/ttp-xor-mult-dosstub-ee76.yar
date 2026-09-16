rule TTP_XOR_MULT_DOSStub_ee76 {
  strings:
    $key_ee76 = { ba 1e [2] ce 06 [2] 89 04 [2] ce 15 [2] 80 19 [2] 8c 13 [2] 9b 18 [2] 80 56 [2] bd }

  condition:
    any of them
}