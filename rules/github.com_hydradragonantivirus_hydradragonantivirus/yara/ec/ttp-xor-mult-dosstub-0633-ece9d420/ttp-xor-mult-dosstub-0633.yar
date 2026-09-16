rule TTP_XOR_MULT_DOSStub_0633 {
  strings:
    $key_0633 = { 52 5b [2] 26 43 [2] 61 41 [2] 26 50 [2] 68 5c [2] 64 56 [2] 73 5d [2] 68 13 [2] 55 }

  condition:
    any of them
}