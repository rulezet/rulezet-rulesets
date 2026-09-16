rule TTP_XOR_MULT_DOSStub_1722 {
  strings:
    $key_1722 = { 43 4a [2] 37 52 [2] 70 50 [2] 37 41 [2] 79 4d [2] 75 47 [2] 62 4c [2] 79 02 [2] 44 }

  condition:
    any of them
}