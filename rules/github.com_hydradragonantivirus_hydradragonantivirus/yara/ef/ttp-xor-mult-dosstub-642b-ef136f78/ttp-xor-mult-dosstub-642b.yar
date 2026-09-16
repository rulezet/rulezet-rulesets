rule TTP_XOR_MULT_DOSStub_642b {
  strings:
    $key_642b = { 30 43 [2] 44 5b [2] 03 59 [2] 44 48 [2] 0a 44 [2] 06 4e [2] 11 45 [2] 0a 0b [2] 37 }

  condition:
    any of them
}