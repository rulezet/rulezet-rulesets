rule TTP_XOR_MULT_DOSStub_516b {
  strings:
    $key_516b = { 05 03 [2] 71 1b [2] 36 19 [2] 71 08 [2] 3f 04 [2] 33 0e [2] 24 05 [2] 3f 4b [2] 02 }

  condition:
    any of them
}