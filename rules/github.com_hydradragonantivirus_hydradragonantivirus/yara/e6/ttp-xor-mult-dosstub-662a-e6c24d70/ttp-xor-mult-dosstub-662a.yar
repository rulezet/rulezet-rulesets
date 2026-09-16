rule TTP_XOR_MULT_DOSStub_662a {
  strings:
    $key_662a = { 32 42 [2] 46 5a [2] 01 58 [2] 46 49 [2] 08 45 [2] 04 4f [2] 13 44 [2] 08 0a [2] 35 }

  condition:
    any of them
}