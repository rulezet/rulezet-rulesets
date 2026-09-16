rule TTP_XOR_MULT_DOSStub_09d0 {
  strings:
    $key_09d0 = { 5d b8 [2] 29 a0 [2] 6e a2 [2] 29 b3 [2] 67 bf [2] 6b b5 [2] 7c be [2] 67 f0 [2] 5a }

  condition:
    any of them
}