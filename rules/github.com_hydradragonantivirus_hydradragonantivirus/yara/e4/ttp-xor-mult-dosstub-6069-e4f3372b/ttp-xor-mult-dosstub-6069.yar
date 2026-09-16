rule TTP_XOR_MULT_DOSStub_6069 {
  strings:
    $key_6069 = { 34 01 [2] 40 19 [2] 07 1b [2] 40 0a [2] 0e 06 [2] 02 0c [2] 15 07 [2] 0e 49 [2] 33 }

  condition:
    any of them
}