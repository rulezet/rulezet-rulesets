rule TTP_XOR_MULT_DOSStub_4469 {
  strings:
    $key_4469 = { 10 01 [2] 64 19 [2] 23 1b [2] 64 0a [2] 2a 06 [2] 26 0c [2] 31 07 [2] 2a 49 [2] 17 }

  condition:
    any of them
}