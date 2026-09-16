rule TTP_XOR_MULT_DOSStub_6423 {
  strings:
    $key_6423 = { 30 4b [2] 44 53 [2] 03 51 [2] 44 40 [2] 0a 4c [2] 06 46 [2] 11 4d [2] 0a 03 [2] 37 }

  condition:
    any of them
}