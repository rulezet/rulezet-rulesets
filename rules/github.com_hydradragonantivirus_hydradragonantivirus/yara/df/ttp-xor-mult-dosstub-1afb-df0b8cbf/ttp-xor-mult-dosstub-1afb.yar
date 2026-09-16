rule TTP_XOR_MULT_DOSStub_1afb {
  strings:
    $key_1afb = { 4e 93 [2] 3a 8b [2] 7d 89 [2] 3a 98 [2] 74 94 [2] 78 9e [2] 6f 95 [2] 74 db [2] 49 }

  condition:
    any of them
}