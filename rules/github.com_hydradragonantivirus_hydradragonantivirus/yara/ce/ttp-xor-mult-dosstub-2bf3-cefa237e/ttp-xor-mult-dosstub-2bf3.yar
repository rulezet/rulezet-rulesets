rule TTP_XOR_MULT_DOSStub_2bf3 {
  strings:
    $key_2bf3 = { 7f 9b [2] 0b 83 [2] 4c 81 [2] 0b 90 [2] 45 9c [2] 49 96 [2] 5e 9d [2] 45 d3 [2] 78 }

  condition:
    any of them
}