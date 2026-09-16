rule TTP_XOR_MULT_DOSStub_68cf {
  strings:
    $key_68cf = { 3c a7 [2] 48 bf [2] 0f bd [2] 48 ac [2] 06 a0 [2] 0a aa [2] 1d a1 [2] 06 ef [2] 3b }

  condition:
    any of them
}