rule TTP_XOR_MULT_DOSStub_ee4d {
  strings:
    $key_ee4d = { ba 25 [2] ce 3d [2] 89 3f [2] ce 2e [2] 80 22 [2] 8c 28 [2] 9b 23 [2] 80 6d [2] bd }

  condition:
    any of them
}