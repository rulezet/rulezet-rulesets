rule TTP_XOR_MULT_DOSStub_eec3 {
  strings:
    $key_eec3 = { ba ab [2] ce b3 [2] 89 b1 [2] ce a0 [2] 80 ac [2] 8c a6 [2] 9b ad [2] 80 e3 [2] bd }

  condition:
    any of them
}