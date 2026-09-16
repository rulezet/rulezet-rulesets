rule TTP_XOR_MULT_DOSStub_3c7b {
  strings:
    $key_3c7b = { 68 13 [2] 1c 0b [2] 5b 09 [2] 1c 18 [2] 52 14 [2] 5e 1e [2] 49 15 [2] 52 5b [2] 6f }

  condition:
    any of them
}