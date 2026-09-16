rule TTP_XOR_MULT_DOSStub_321b {
  strings:
    $key_321b = { 66 73 [2] 12 6b [2] 55 69 [2] 12 78 [2] 5c 74 [2] 50 7e [2] 47 75 [2] 5c 3b [2] 61 }

  condition:
    any of them
}