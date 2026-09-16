rule TTP_XOR_MULT_DOSStub_bbf3 {
  strings:
    $key_bbf3 = { ef 9b [2] 9b 83 [2] dc 81 [2] 9b 90 [2] d5 9c [2] d9 96 [2] ce 9d [2] d5 d3 [2] e8 }

  condition:
    any of them
}