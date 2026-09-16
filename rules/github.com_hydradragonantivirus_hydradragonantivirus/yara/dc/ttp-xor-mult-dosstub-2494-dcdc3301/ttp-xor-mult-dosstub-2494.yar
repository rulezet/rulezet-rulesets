rule TTP_XOR_MULT_DOSStub_2494 {
  strings:
    $key_2494 = { 70 fc [2] 04 e4 [2] 43 e6 [2] 04 f7 [2] 4a fb [2] 46 f1 [2] 51 fa [2] 4a b4 [2] 77 }

  condition:
    any of them
}