rule TTP_XOR_MULT_DOSStub_3bfb {
  strings:
    $key_3bfb = { 6f 93 [2] 1b 8b [2] 5c 89 [2] 1b 98 [2] 55 94 [2] 59 9e [2] 4e 95 [2] 55 db [2] 68 }

  condition:
    any of them
}