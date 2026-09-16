rule TTP_XOR_MULT_DOSStub_7217 {
  strings:
    $key_7217 = { 26 7f [2] 52 67 [2] 15 65 [2] 52 74 [2] 1c 78 [2] 10 72 [2] 07 79 [2] 1c 37 [2] 21 }

  condition:
    any of them
}