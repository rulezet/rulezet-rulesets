rule TTP_XOR_MULT_DOSStub_0f7b {
  strings:
    $key_0f7b = { 5b 13 [2] 2f 0b [2] 68 09 [2] 2f 18 [2] 61 14 [2] 6d 1e [2] 7a 15 [2] 61 5b [2] 5c }

  condition:
    any of them
}