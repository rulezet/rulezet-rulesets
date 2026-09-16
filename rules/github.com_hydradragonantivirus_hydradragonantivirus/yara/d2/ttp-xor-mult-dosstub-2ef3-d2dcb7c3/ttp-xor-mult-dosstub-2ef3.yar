rule TTP_XOR_MULT_DOSStub_2ef3 {
  strings:
    $key_2ef3 = { 7a 9b [2] 0e 83 [2] 49 81 [2] 0e 90 [2] 40 9c [2] 4c 96 [2] 5b 9d [2] 40 d3 [2] 7d }

  condition:
    any of them
}