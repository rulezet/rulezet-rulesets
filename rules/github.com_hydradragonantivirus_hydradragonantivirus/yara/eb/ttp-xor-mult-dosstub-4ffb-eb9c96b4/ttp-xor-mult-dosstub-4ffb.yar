rule TTP_XOR_MULT_DOSStub_4ffb {
  strings:
    $key_4ffb = { 1b 93 [2] 6f 8b [2] 28 89 [2] 6f 98 [2] 21 94 [2] 2d 9e [2] 3a 95 [2] 21 db [2] 1c }

  condition:
    any of them
}