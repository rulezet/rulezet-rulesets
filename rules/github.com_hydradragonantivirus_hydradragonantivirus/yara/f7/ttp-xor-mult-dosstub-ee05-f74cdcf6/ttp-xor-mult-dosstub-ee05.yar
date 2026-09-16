rule TTP_XOR_MULT_DOSStub_ee05 {
  strings:
    $key_ee05 = { ba 6d [2] ce 75 [2] 89 77 [2] ce 66 [2] 80 6a [2] 8c 60 [2] 9b 6b [2] 80 25 [2] bd }

  condition:
    any of them
}