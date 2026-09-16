rule TTP_XOR_MULT_DOSStub_8f1e {
  strings:
    $key_8f1e = { db 76 [2] af 6e [2] e8 6c [2] af 7d [2] e1 71 [2] ed 7b [2] fa 70 [2] e1 3e [2] dc }

  condition:
    any of them
}