rule TTP_XOR_MULT_DOSStub_ee32 {
  strings:
    $key_ee32 = { ba 5a [2] ce 42 [2] 89 40 [2] ce 51 [2] 80 5d [2] 8c 57 [2] 9b 5c [2] 80 12 [2] bd }

  condition:
    any of them
}