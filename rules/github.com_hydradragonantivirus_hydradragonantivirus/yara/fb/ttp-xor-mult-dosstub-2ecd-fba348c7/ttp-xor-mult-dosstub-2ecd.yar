rule TTP_XOR_MULT_DOSStub_2ecd {
  strings:
    $key_2ecd = { 7a a5 [2] 0e bd [2] 49 bf [2] 0e ae [2] 40 a2 [2] 4c a8 [2] 5b a3 [2] 40 ed [2] 7d }

  condition:
    any of them
}