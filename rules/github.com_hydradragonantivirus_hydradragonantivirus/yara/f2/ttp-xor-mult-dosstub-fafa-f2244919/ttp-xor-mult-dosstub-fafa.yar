rule TTP_XOR_MULT_DOSStub_fafa {
  strings:
    $key_fafa = { ae 92 [2] da 8a [2] 9d 88 [2] da 99 [2] 94 95 [2] 98 9f [2] 8f 94 [2] 94 da [2] a9 }

  condition:
    any of them
}