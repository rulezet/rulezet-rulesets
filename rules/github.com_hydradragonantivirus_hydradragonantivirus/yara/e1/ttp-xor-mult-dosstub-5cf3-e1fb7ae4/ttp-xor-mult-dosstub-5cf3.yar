rule TTP_XOR_MULT_DOSStub_5cf3 {
  strings:
    $key_5cf3 = { 08 9b [2] 7c 83 [2] 3b 81 [2] 7c 90 [2] 32 9c [2] 3e 96 [2] 29 9d [2] 32 d3 [2] 0f }

  condition:
    any of them
}