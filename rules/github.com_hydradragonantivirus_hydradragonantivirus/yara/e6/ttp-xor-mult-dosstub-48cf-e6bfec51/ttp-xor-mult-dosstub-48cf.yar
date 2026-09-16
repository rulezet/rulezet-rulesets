rule TTP_XOR_MULT_DOSStub_48cf {
  strings:
    $key_48cf = { 1c a7 [2] 68 bf [2] 2f bd [2] 68 ac [2] 26 a0 [2] 2a aa [2] 3d a1 [2] 26 ef [2] 1b }

  condition:
    any of them
}