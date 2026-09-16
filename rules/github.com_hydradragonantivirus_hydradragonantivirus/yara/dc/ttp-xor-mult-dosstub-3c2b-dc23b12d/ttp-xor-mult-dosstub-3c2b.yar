rule TTP_XOR_MULT_DOSStub_3c2b {
  strings:
    $key_3c2b = { 68 43 [2] 1c 5b [2] 5b 59 [2] 1c 48 [2] 52 44 [2] 5e 4e [2] 49 45 [2] 52 0b [2] 6f }

  condition:
    any of them
}