rule TTP_XOR_MULT_DOSStub_b2da {
  strings:
    $key_b2da = { e6 b2 [2] 92 aa [2] d5 a8 [2] 92 b9 [2] dc b5 [2] d0 bf [2] c7 b4 [2] dc fa [2] e1 }

  condition:
    any of them
}