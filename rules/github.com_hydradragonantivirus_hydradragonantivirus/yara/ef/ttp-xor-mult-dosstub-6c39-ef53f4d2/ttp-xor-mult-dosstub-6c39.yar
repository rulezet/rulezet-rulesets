rule TTP_XOR_MULT_DOSStub_6c39 {
  strings:
    $key_6c39 = { 38 51 [2] 4c 49 [2] 0b 4b [2] 4c 5a [2] 02 56 [2] 0e 5c [2] 19 57 [2] 02 19 [2] 3f }

  condition:
    any of them
}