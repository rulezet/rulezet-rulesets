rule TTP_XOR_MULT_DOSStub_7cfb {
  strings:
    $key_7cfb = { 28 93 [2] 5c 8b [2] 1b 89 [2] 5c 98 [2] 12 94 [2] 1e 9e [2] 09 95 [2] 12 db [2] 2f }

  condition:
    any of them
}