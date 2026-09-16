rule TTP_XOR_MULT_DOSStub_ee06 {
  strings:
    $key_ee06 = { ba 6e [2] ce 76 [2] 89 74 [2] ce 65 [2] 80 69 [2] 8c 63 [2] 9b 68 [2] 80 26 [2] bd }

  condition:
    any of them
}