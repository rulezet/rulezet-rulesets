rule TTP_XOR_MULT_DOSStub_d3da {
  strings:
    $key_d3da = { 87 b2 [2] f3 aa [2] b4 a8 [2] f3 b9 [2] bd b5 [2] b1 bf [2] a6 b4 [2] bd fa [2] 80 }

  condition:
    any of them
}