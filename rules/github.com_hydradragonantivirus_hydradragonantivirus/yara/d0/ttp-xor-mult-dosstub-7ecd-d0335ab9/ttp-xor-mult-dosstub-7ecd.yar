rule TTP_XOR_MULT_DOSStub_7ecd {
  strings:
    $key_7ecd = { 2a a5 [2] 5e bd [2] 19 bf [2] 5e ae [2] 10 a2 [2] 1c a8 [2] 0b a3 [2] 10 ed [2] 2d }

  condition:
    any of them
}