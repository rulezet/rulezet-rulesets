rule TTP_XOR_MULT_DOSStub_fafb {
  strings:
    $key_fafb = { ae 93 [2] da 8b [2] 9d 89 [2] da 98 [2] 94 94 [2] 98 9e [2] 8f 95 [2] 94 db [2] a9 }

  condition:
    any of them
}