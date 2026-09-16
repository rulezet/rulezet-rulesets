rule TTP_XOR_MULT_DOSStub_7722 {
  strings:
    $key_7722 = { 23 4a [2] 57 52 [2] 10 50 [2] 57 41 [2] 19 4d [2] 15 47 [2] 02 4c [2] 19 02 [2] 24 }

  condition:
    any of them
}