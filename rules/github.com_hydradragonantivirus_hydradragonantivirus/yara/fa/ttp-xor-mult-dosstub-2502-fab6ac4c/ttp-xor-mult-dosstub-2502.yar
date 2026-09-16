rule TTP_XOR_MULT_DOSStub_2502 {
  strings:
    $key_2502 = { 71 6a [2] 05 72 [2] 42 70 [2] 05 61 [2] 4b 6d [2] 47 67 [2] 50 6c [2] 4b 22 [2] 76 }

  condition:
    any of them
}