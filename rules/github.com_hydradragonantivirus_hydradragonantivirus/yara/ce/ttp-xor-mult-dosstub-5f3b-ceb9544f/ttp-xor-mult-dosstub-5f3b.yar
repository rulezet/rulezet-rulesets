rule TTP_XOR_MULT_DOSStub_5f3b {
  strings:
    $key_5f3b = { 0b 53 [2] 7f 4b [2] 38 49 [2] 7f 58 [2] 31 54 [2] 3d 5e [2] 2a 55 [2] 31 1b [2] 0c }

  condition:
    any of them
}