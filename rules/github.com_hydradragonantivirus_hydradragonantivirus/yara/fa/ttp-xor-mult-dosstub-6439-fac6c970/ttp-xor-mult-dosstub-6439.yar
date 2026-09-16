rule TTP_XOR_MULT_DOSStub_6439 {
  strings:
    $key_6439 = { 30 51 [2] 44 49 [2] 03 4b [2] 44 5a [2] 0a 56 [2] 06 5c [2] 11 57 [2] 0a 19 [2] 37 }

  condition:
    any of them
}