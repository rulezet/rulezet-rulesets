rule TTP_XOR_MULT_DOSStub_79da {
  strings:
    $key_79da = { 2d b2 [2] 59 aa [2] 1e a8 [2] 59 b9 [2] 17 b5 [2] 1b bf [2] 0c b4 [2] 17 fa [2] 2a }

  condition:
    any of them
}