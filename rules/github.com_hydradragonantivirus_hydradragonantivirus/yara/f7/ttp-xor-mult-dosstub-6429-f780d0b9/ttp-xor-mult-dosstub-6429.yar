rule TTP_XOR_MULT_DOSStub_6429 {
  strings:
    $key_6429 = { 30 41 [2] 44 59 [2] 03 5b [2] 44 4a [2] 0a 46 [2] 06 4c [2] 11 47 [2] 0a 09 [2] 37 }

  condition:
    any of them
}