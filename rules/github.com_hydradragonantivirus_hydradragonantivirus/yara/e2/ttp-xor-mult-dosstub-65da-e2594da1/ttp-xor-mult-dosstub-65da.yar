rule TTP_XOR_MULT_DOSStub_65da {
  strings:
    $key_65da = { 31 b2 [2] 45 aa [2] 02 a8 [2] 45 b9 [2] 0b b5 [2] 07 bf [2] 10 b4 [2] 0b fa [2] 36 }

  condition:
    any of them
}