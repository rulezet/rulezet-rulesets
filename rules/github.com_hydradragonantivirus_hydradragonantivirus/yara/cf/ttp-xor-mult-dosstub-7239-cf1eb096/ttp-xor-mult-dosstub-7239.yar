rule TTP_XOR_MULT_DOSStub_7239 {
  strings:
    $key_7239 = { 26 51 [2] 52 49 [2] 15 4b [2] 52 5a [2] 1c 56 [2] 10 5c [2] 07 57 [2] 1c 19 [2] 21 }

  condition:
    any of them
}