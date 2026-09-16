rule TTP_XOR_MULT_DOSStub_1cf3 {
  strings:
    $key_1cf3 = { 48 9b [2] 3c 83 [2] 7b 81 [2] 3c 90 [2] 72 9c [2] 7e 96 [2] 69 9d [2] 72 d3 [2] 4f }

  condition:
    any of them
}