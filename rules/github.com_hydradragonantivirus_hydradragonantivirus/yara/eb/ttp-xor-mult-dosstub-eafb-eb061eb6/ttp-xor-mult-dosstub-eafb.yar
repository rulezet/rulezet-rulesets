rule TTP_XOR_MULT_DOSStub_eafb {
  strings:
    $key_eafb = { be 93 [2] ca 8b [2] 8d 89 [2] ca 98 [2] 84 94 [2] 88 9e [2] 9f 95 [2] 84 db [2] b9 }

  condition:
    any of them
}