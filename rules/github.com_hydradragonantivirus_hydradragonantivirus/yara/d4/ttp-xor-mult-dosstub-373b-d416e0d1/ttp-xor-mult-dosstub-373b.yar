rule TTP_XOR_MULT_DOSStub_373b {
  strings:
    $key_373b = { 63 53 [2] 17 4b [2] 50 49 [2] 17 58 [2] 59 54 [2] 55 5e [2] 42 55 [2] 59 1b [2] 64 }

  condition:
    any of them
}