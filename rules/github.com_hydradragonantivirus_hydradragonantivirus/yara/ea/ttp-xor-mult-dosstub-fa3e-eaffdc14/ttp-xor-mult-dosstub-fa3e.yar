rule TTP_XOR_MULT_DOSStub_fa3e {
  strings:
    $key_fa3e = { ae 56 [2] da 4e [2] 9d 4c [2] da 5d [2] 94 51 [2] 98 5b [2] 8f 50 [2] 94 1e [2] a9 }

  condition:
    any of them
}