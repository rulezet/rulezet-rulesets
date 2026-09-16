rule TTP_XOR_MULT_DOSStub_eeda {
  strings:
    $key_eeda = { ba b2 [2] ce aa [2] 89 a8 [2] ce b9 [2] 80 b5 [2] 8c bf [2] 9b b4 [2] 80 fa [2] bd }

  condition:
    any of them
}