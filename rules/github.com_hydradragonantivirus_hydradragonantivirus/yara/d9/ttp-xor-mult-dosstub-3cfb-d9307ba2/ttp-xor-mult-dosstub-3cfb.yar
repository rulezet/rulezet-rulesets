rule TTP_XOR_MULT_DOSStub_3cfb {
  strings:
    $key_3cfb = { 68 93 [2] 1c 8b [2] 5b 89 [2] 1c 98 [2] 52 94 [2] 5e 9e [2] 49 95 [2] 52 db [2] 6f }

  condition:
    any of them
}