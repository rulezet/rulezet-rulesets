rule TTP_XOR_MULT_DOSStub_3fcd {
  strings:
    $key_3fcd = { 6b a5 [2] 1f bd [2] 58 bf [2] 1f ae [2] 51 a2 [2] 5d a8 [2] 4a a3 [2] 51 ed [2] 6c }

  condition:
    any of them
}