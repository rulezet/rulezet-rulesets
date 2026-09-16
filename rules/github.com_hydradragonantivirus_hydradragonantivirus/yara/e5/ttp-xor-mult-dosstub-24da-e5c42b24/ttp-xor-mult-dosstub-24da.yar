rule TTP_XOR_MULT_DOSStub_24da {
  strings:
    $key_24da = { 70 b2 [2] 04 aa [2] 43 a8 [2] 04 b9 [2] 4a b5 [2] 46 bf [2] 51 b4 [2] 4a fa [2] 77 }

  condition:
    any of them
}