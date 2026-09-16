rule TTP_XOR_MULT_DOSStub_87da {
  strings:
    $key_87da = { d3 b2 [2] a7 aa [2] e0 a8 [2] a7 b9 [2] e9 b5 [2] e5 bf [2] f2 b4 [2] e9 fa [2] d4 }

  condition:
    any of them
}