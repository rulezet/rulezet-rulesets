rule TTP_XOR_MULT_DOSStub_7769 {
  strings:
    $key_7769 = { 23 01 [2] 57 19 [2] 10 1b [2] 57 0a [2] 19 06 [2] 15 0c [2] 02 07 [2] 19 49 [2] 24 }

  condition:
    any of them
}