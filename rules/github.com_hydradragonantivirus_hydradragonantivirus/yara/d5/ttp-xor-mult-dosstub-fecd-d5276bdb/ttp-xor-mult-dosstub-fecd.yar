rule TTP_XOR_MULT_DOSStub_fecd {
  strings:
    $key_fecd = { aa a5 [2] de bd [2] 99 bf [2] de ae [2] 90 a2 [2] 9c a8 [2] 8b a3 [2] 90 ed [2] ad }

  condition:
    any of them
}