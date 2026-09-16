rule TTP_XOR_MULT_DOSStub_29d0 {
  strings:
    $key_29d0 = { 7d b8 [2] 09 a0 [2] 4e a2 [2] 09 b3 [2] 47 bf [2] 4b b5 [2] 5c be [2] 47 f0 [2] 7a }

  condition:
    any of them
}