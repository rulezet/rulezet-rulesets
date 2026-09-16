rule TTP_XOR_MULT_DOSStub_6f5b {
  strings:
    $key_6f5b = { 3b 33 [2] 4f 2b [2] 08 29 [2] 4f 38 [2] 01 34 [2] 0d 3e [2] 1a 35 [2] 01 7b [2] 3c }

  condition:
    any of them
}