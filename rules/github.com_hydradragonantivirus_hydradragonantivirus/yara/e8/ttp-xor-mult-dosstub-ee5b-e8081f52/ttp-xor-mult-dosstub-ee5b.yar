rule TTP_XOR_MULT_DOSStub_ee5b {
  strings:
    $key_ee5b = { ba 33 [2] ce 2b [2] 89 29 [2] ce 38 [2] 80 34 [2] 8c 3e [2] 9b 35 [2] 80 7b [2] bd }

  condition:
    any of them
}