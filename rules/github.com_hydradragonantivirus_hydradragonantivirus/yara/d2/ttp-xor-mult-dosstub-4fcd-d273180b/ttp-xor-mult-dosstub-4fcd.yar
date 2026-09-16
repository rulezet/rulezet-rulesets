rule TTP_XOR_MULT_DOSStub_4fcd {
  strings:
    $key_4fcd = { 1b a5 [2] 6f bd [2] 28 bf [2] 6f ae [2] 21 a2 [2] 2d a8 [2] 3a a3 [2] 21 ed [2] 1c }

  condition:
    any of them
}