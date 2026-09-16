rule TTP_XOR_MULT_DOSStub_19d0 {
  strings:
    $key_19d0 = { 4d b8 [2] 39 a0 [2] 7e a2 [2] 39 b3 [2] 77 bf [2] 7b b5 [2] 6c be [2] 77 f0 [2] 4a }

  condition:
    any of them
}