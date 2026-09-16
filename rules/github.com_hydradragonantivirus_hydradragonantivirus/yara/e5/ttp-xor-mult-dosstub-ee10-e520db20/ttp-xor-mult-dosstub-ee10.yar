rule TTP_XOR_MULT_DOSStub_ee10 {
  strings:
    $key_ee10 = { ba 78 [2] ce 60 [2] 89 62 [2] ce 73 [2] 80 7f [2] 8c 75 [2] 9b 7e [2] 80 30 [2] bd }

  condition:
    any of them
}