rule TTP_XOR_MULT_DOSStub_2efb {
  strings:
    $key_2efb = { 7a 93 [2] 0e 8b [2] 49 89 [2] 0e 98 [2] 40 94 [2] 4c 9e [2] 5b 95 [2] 40 db [2] 7d }

  condition:
    any of them
}