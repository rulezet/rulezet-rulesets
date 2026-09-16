rule TTP_XOR_MULT_DOSStub_4ef3 {
  strings:
    $key_4ef3 = { 1a 9b [2] 6e 83 [2] 29 81 [2] 6e 90 [2] 20 9c [2] 2c 96 [2] 3b 9d [2] 20 d3 [2] 1d }

  condition:
    any of them
}