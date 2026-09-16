rule TTP_XOR_MULT_DOSStub_ee66 {
  strings:
    $key_ee66 = { ba 0e [2] ce 16 [2] 89 14 [2] ce 05 [2] 80 09 [2] 8c 03 [2] 9b 08 [2] 80 46 [2] bd }

  condition:
    any of them
}