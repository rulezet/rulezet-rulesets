rule TTP_XOR_MULT_DOSStub_7e3b {
  strings:
    $key_7e3b = { 2a 53 [2] 5e 4b [2] 19 49 [2] 5e 58 [2] 10 54 [2] 1c 5e [2] 0b 55 [2] 10 1b [2] 2d }

  condition:
    any of them
}