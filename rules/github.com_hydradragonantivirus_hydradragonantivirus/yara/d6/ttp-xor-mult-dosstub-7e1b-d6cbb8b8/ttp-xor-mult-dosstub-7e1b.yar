rule TTP_XOR_MULT_DOSStub_7e1b {
  strings:
    $key_7e1b = { 2a 73 [2] 5e 6b [2] 19 69 [2] 5e 78 [2] 10 74 [2] 1c 7e [2] 0b 75 [2] 10 3b [2] 2d }

  condition:
    any of them
}