rule TTP_XOR_MULT_DOSStub_6e3b {
  strings:
    $key_6e3b = { 3a 53 [2] 4e 4b [2] 09 49 [2] 4e 58 [2] 00 54 [2] 0c 5e [2] 1b 55 [2] 00 1b [2] 3d }

  condition:
    any of them
}