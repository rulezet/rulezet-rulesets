rule TTP_XOR_MULT_DOSStub_1efb {
  strings:
    $key_1efb = { 4a 93 [2] 3e 8b [2] 79 89 [2] 3e 98 [2] 70 94 [2] 7c 9e [2] 6b 95 [2] 70 db [2] 4d }

  condition:
    any of them
}