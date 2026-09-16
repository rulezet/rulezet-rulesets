rule TTP_XOR_MULT_DOSStub_2522 {
  strings:
    $key_2522 = { 71 4a [2] 05 52 [2] 42 50 [2] 05 41 [2] 4b 4d [2] 47 47 [2] 50 4c [2] 4b 02 [2] 76 }

  condition:
    any of them
}