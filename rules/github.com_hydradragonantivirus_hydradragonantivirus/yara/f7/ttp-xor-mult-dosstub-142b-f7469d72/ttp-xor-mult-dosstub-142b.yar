rule TTP_XOR_MULT_DOSStub_142b {
  strings:
    $key_142b = { 40 43 [2] 34 5b [2] 73 59 [2] 34 48 [2] 7a 44 [2] 76 4e [2] 61 45 [2] 7a 0b [2] 47 }

  condition:
    any of them
}