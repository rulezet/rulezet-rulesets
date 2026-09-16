rule TTP_XOR_MULT_DOSStub_0afa {
  strings:
    $key_0afa = { 5e 92 [2] 2a 8a [2] 6d 88 [2] 2a 99 [2] 64 95 [2] 68 9f [2] 7f 94 [2] 64 da [2] 59 }

  condition:
    any of them
}