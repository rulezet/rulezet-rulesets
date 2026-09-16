rule TTP_XOR_MULT_DOSStub_6efb {
  strings:
    $key_6efb = { 3a 93 [2] 4e 8b [2] 09 89 [2] 4e 98 [2] 00 94 [2] 0c 9e [2] 1b 95 [2] 00 db [2] 3d }

  condition:
    any of them
}