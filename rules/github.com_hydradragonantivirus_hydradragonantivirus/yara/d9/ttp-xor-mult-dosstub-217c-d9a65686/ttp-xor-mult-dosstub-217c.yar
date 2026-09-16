rule TTP_XOR_MULT_DOSStub_217c {
  strings:
    $key_217c = { 75 14 [2] 01 0c [2] 46 0e [2] 01 1f [2] 4f 13 [2] 43 19 [2] 54 12 [2] 4f 5c [2] 72 }

  condition:
    any of them
}