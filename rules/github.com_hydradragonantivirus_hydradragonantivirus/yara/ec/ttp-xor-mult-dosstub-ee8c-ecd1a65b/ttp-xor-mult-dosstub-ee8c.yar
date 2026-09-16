rule TTP_XOR_MULT_DOSStub_ee8c {
  strings:
    $key_ee8c = { ba e4 [2] ce fc [2] 89 fe [2] ce ef [2] 80 e3 [2] 8c e9 [2] 9b e2 [2] 80 ac [2] bd }

  condition:
    any of them
}