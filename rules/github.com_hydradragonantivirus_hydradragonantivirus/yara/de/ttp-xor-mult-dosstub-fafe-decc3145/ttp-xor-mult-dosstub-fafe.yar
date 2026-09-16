rule TTP_XOR_MULT_DOSStub_fafe {
  strings:
    $key_fafe = { ae 96 [2] da 8e [2] 9d 8c [2] da 9d [2] 94 91 [2] 98 9b [2] 8f 90 [2] 94 de [2] a9 }

  condition:
    any of them
}