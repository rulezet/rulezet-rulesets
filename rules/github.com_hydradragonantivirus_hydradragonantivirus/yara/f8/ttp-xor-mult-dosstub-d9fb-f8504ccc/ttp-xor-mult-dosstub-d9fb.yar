rule TTP_XOR_MULT_DOSStub_d9fb {
  strings:
    $key_d9fb = { 8d 93 [2] f9 8b [2] be 89 [2] f9 98 [2] b7 94 [2] bb 9e [2] ac 95 [2] b7 db [2] 8a }

  condition:
    any of them
}