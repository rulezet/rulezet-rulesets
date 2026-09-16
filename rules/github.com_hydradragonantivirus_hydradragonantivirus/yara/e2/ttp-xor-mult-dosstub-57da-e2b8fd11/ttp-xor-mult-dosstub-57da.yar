rule TTP_XOR_MULT_DOSStub_57da {
  strings:
    $key_57da = { 03 b2 [2] 77 aa [2] 30 a8 [2] 77 b9 [2] 39 b5 [2] 35 bf [2] 22 b4 [2] 39 fa [2] 04 }

  condition:
    any of them
}