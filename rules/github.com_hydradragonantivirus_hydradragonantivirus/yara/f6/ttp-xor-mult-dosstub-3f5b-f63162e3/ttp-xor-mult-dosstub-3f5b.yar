rule TTP_XOR_MULT_DOSStub_3f5b {
  strings:
    $key_3f5b = { 6b 33 [2] 1f 2b [2] 58 29 [2] 1f 38 [2] 51 34 [2] 5d 3e [2] 4a 35 [2] 51 7b [2] 6c }

  condition:
    any of them
}