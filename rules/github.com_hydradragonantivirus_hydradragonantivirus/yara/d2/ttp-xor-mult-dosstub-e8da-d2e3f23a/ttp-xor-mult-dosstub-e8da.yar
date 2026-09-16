rule TTP_XOR_MULT_DOSStub_e8da {
  strings:
    $key_e8da = { bc b2 [2] c8 aa [2] 8f a8 [2] c8 b9 [2] 86 b5 [2] 8a bf [2] 9d b4 [2] 86 fa [2] bb }

  condition:
    any of them
}