rule TTP_XOR_MULT_DOSStub_4afb {
  strings:
    $key_4afb = { 1e 93 [2] 6a 8b [2] 2d 89 [2] 6a 98 [2] 24 94 [2] 28 9e [2] 3f 95 [2] 24 db [2] 19 }

  condition:
    any of them
}