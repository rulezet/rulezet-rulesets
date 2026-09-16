rule TTP_XOR_MULT_DOSStub_2ce2 {
  strings:
    $key_2ce2 = { 78 8a [2] 0c 92 [2] 4b 90 [2] 0c 81 [2] 42 8d [2] 4e 87 [2] 59 8c [2] 42 c2 [2] 7f }

  condition:
    any of them
}