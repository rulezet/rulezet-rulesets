rule TTP_XOR_MULT_DOSStub_6df3 {
  strings:
    $key_6df3 = { 39 9b [2] 4d 83 [2] 0a 81 [2] 4d 90 [2] 03 9c [2] 0f 96 [2] 18 9d [2] 03 d3 [2] 3e }

  condition:
    any of them
}