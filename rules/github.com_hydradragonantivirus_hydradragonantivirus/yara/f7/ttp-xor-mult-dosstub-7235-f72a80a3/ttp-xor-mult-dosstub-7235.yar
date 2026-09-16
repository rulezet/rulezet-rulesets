rule TTP_XOR_MULT_DOSStub_7235 {
  strings:
    $key_7235 = { 26 5d [2] 52 45 [2] 15 47 [2] 52 56 [2] 1c 5a [2] 10 50 [2] 07 5b [2] 1c 15 [2] 21 }

  condition:
    any of them
}