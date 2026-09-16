rule TTP_XOR_MULT_DOSStub_7262 {
  strings:
    $key_7262 = { 26 0a [2] 52 12 [2] 15 10 [2] 52 01 [2] 1c 0d [2] 10 07 [2] 07 0c [2] 1c 42 [2] 21 }

  condition:
    any of them
}