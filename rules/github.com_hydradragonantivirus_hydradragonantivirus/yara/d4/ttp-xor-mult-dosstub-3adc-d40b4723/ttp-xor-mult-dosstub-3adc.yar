rule TTP_XOR_MULT_DOSStub_3adc {
  strings:
    $key_3adc = { 6e b4 [2] 1a ac [2] 5d ae [2] 1a bf [2] 54 b3 [2] 58 b9 [2] 4f b2 [2] 54 fc [2] 69 }

  condition:
    any of them
}