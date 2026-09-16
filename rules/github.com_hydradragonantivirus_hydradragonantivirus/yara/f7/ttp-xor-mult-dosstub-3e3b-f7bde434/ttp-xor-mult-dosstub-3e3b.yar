rule TTP_XOR_MULT_DOSStub_3e3b {
  strings:
    $key_3e3b = { 6a 53 [2] 1e 4b [2] 59 49 [2] 1e 58 [2] 50 54 [2] 5c 5e [2] 4b 55 [2] 50 1b [2] 6d }

  condition:
    any of them
}