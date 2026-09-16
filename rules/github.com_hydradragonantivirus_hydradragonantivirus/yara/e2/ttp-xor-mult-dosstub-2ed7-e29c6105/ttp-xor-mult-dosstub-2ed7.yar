rule TTP_XOR_MULT_DOSStub_2ed7 {
  strings:
    $key_2ed7 = { 7a bf [2] 0e a7 [2] 49 a5 [2] 0e b4 [2] 40 b8 [2] 4c b2 [2] 5b b9 [2] 40 f7 [2] 7d }

  condition:
    any of them
}