rule TTP_XOR_MULT_DOSStub_3c3b {
  strings:
    $key_3c3b = { 68 53 [2] 1c 4b [2] 5b 49 [2] 1c 58 [2] 52 54 [2] 5e 5e [2] 49 55 [2] 52 1b [2] 6f }

  condition:
    any of them
}