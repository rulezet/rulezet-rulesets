rule TTP_XOR_MULT_DOSStub_09fb {
  strings:
    $key_09fb = { 5d 93 [2] 29 8b [2] 6e 89 [2] 29 98 [2] 67 94 [2] 6b 9e [2] 7c 95 [2] 67 db [2] 5a }

  condition:
    any of them
}