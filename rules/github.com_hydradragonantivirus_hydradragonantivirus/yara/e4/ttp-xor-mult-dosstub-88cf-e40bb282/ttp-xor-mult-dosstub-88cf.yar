rule TTP_XOR_MULT_DOSStub_88cf {
  strings:
    $key_88cf = { dc a7 [2] a8 bf [2] ef bd [2] a8 ac [2] e6 a0 [2] ea aa [2] fd a1 [2] e6 ef [2] db }

  condition:
    any of them
}