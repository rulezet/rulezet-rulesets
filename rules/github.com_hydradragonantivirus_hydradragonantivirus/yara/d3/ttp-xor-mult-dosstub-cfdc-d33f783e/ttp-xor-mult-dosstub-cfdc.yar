rule TTP_XOR_MULT_DOSStub_cfdc {
  strings:
    $key_cfdc = { 9b b4 [2] ef ac [2] a8 ae [2] ef bf [2] a1 b3 [2] ad b9 [2] ba b2 [2] a1 fc [2] 9c }

  condition:
    any of them
}