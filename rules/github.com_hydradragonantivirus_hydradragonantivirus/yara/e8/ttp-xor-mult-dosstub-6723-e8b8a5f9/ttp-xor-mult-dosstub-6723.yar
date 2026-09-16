rule TTP_XOR_MULT_DOSStub_6723 {
  strings:
    $key_6723 = { 33 4b [2] 47 53 [2] 00 51 [2] 47 40 [2] 09 4c [2] 05 46 [2] 12 4d [2] 09 03 [2] 34 }

  condition:
    any of them
}