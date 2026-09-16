rule TTP_XOR_MULT_DOSStub_3f3b {
  strings:
    $key_3f3b = { 6b 53 [2] 1f 4b [2] 58 49 [2] 1f 58 [2] 51 54 [2] 5d 5e [2] 4a 55 [2] 51 1b [2] 6c }

  condition:
    any of them
}