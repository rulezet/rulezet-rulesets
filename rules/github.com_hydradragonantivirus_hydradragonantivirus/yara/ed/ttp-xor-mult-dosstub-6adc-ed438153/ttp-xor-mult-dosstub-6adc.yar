rule TTP_XOR_MULT_DOSStub_6adc {
  strings:
    $key_6adc = { 3e b4 [2] 4a ac [2] 0d ae [2] 4a bf [2] 04 b3 [2] 08 b9 [2] 1f b2 [2] 04 fc [2] 39 }

  condition:
    any of them
}