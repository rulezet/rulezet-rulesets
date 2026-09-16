rule TTP_XOR_MULT_DOSStub_5cfb {
  strings:
    $key_5cfb = { 08 93 [2] 7c 8b [2] 3b 89 [2] 7c 98 [2] 32 94 [2] 3e 9e [2] 29 95 [2] 32 db [2] 0f }

  condition:
    any of them
}