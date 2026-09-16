rule TTP_XOR_MULT_DOSStub_eedc {
  strings:
    $key_eedc = { ba b4 [2] ce ac [2] 89 ae [2] ce bf [2] 80 b3 [2] 8c b9 [2] 9b b2 [2] 80 fc [2] bd }

  condition:
    any of them
}