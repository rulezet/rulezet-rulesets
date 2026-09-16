rule TTP_XOR_MULT_DOSStub_2eda {
  strings:
    $key_2eda = { 7a b2 [2] 0e aa [2] 49 a8 [2] 0e b9 [2] 40 b5 [2] 4c bf [2] 5b b4 [2] 40 fa [2] 7d }

  condition:
    any of them
}