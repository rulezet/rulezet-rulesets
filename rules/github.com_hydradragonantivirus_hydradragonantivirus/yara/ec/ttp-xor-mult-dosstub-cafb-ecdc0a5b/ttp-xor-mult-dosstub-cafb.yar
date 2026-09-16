rule TTP_XOR_MULT_DOSStub_cafb {
  strings:
    $key_cafb = { 9e 93 [2] ea 8b [2] ad 89 [2] ea 98 [2] a4 94 [2] a8 9e [2] bf 95 [2] a4 db [2] 99 }

  condition:
    any of them
}