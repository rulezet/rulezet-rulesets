rule TTP_XOR_MULT_DOSStub_effb {
  strings:
    $key_effb = { bb 93 [2] cf 8b [2] 88 89 [2] cf 98 [2] 81 94 [2] 8d 9e [2] 9a 95 [2] 81 db [2] bc }

  condition:
    any of them
}