rule TTP_XOR_MULT_DOSStub_faec {
  strings:
    $key_faec = { ae 84 [2] da 9c [2] 9d 9e [2] da 8f [2] 94 83 [2] 98 89 [2] 8f 82 [2] 94 cc [2] a9 }

  condition:
    any of them
}