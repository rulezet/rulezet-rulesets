rule TTP_XOR_MULT_DOSStub_251c {
  strings:
    $key_251c = { 71 74 [2] 05 6c [2] 42 6e [2] 05 7f [2] 4b 73 [2] 47 79 [2] 50 72 [2] 4b 3c [2] 76 }

  condition:
    any of them
}