rule TTP_XOR_MULT_DOSStub_dafb {
  strings:
    $key_dafb = { 8e 93 [2] fa 8b [2] bd 89 [2] fa 98 [2] b4 94 [2] b8 9e [2] af 95 [2] b4 db [2] 89 }

  condition:
    any of them
}