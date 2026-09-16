rule TTP_XOR_MULT_DOSStub_6afb {
  strings:
    $key_6afb = { 3e 93 [2] 4a 8b [2] 0d 89 [2] 4a 98 [2] 04 94 [2] 08 9e [2] 1f 95 [2] 04 db [2] 39 }

  condition:
    any of them
}