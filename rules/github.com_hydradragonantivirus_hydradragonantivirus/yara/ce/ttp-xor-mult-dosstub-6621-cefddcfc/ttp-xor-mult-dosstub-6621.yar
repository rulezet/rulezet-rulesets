rule TTP_XOR_MULT_DOSStub_6621 {
  strings:
    $key_6621 = { 32 49 [2] 46 51 [2] 01 53 [2] 46 42 [2] 08 4e [2] 04 44 [2] 13 4f [2] 08 01 [2] 35 }

  condition:
    any of them
}