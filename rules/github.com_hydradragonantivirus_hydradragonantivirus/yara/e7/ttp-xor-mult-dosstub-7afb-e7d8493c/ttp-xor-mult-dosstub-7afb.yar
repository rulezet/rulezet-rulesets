rule TTP_XOR_MULT_DOSStub_7afb {
  strings:
    $key_7afb = { 2e 93 [2] 5a 8b [2] 1d 89 [2] 5a 98 [2] 14 94 [2] 18 9e [2] 0f 95 [2] 14 db [2] 29 }

  condition:
    any of them
}