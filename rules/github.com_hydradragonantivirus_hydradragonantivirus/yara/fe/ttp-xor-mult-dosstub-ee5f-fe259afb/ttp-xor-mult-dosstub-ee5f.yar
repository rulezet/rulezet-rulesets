rule TTP_XOR_MULT_DOSStub_ee5f {
  strings:
    $key_ee5f = { ba 37 [2] ce 2f [2] 89 2d [2] ce 3c [2] 80 30 [2] 8c 3a [2] 9b 31 [2] 80 7f [2] bd }

  condition:
    any of them
}