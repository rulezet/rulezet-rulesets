rule TTP_XOR_MULT_DOSStub_6bf3 {
  strings:
    $key_6bf3 = { 3f 9b [2] 4b 83 [2] 0c 81 [2] 4b 90 [2] 05 9c [2] 09 96 [2] 1e 9d [2] 05 d3 [2] 38 }

  condition:
    any of them
}