rule TTP_XOR_MULT_DOSStub_7e6b {
  strings:
    $key_7e6b = { 2a 03 [2] 5e 1b [2] 19 19 [2] 5e 08 [2] 10 04 [2] 1c 0e [2] 0b 05 [2] 10 4b [2] 2d }

  condition:
    any of them
}