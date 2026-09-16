rule TTP_XOR_MULT_DOSStub_7222 {
  strings:
    $key_7222 = { 26 4a [2] 52 52 [2] 15 50 [2] 52 41 [2] 1c 4d [2] 10 47 [2] 07 4c [2] 1c 02 [2] 21 }

  condition:
    any of them
}