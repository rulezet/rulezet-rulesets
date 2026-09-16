rule TTP_XOR_MULT_DOSStub_4cfb {
  strings:
    $key_4cfb = { 18 93 [2] 6c 8b [2] 2b 89 [2] 6c 98 [2] 22 94 [2] 2e 9e [2] 39 95 [2] 22 db [2] 1f }

  condition:
    any of them
}