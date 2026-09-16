rule TTP_XOR_MULT_DOSStub_1bfb {
  strings:
    $key_1bfb = { 4f 93 [2] 3b 8b [2] 7c 89 [2] 3b 98 [2] 75 94 [2] 79 9e [2] 6e 95 [2] 75 db [2] 48 }

  condition:
    any of them
}