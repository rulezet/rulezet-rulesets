rule TTP_XOR_MULT_DOSStub_0ef3 {
  strings:
    $key_0ef3 = { 5a 9b [2] 2e 83 [2] 69 81 [2] 2e 90 [2] 60 9c [2] 6c 96 [2] 7b 9d [2] 60 d3 [2] 5d }

  condition:
    any of them
}