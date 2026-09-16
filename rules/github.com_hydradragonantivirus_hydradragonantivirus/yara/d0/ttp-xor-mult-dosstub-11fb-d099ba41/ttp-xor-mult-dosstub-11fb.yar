rule TTP_XOR_MULT_DOSStub_11fb {
  strings:
    $key_11fb = { 45 93 [2] 31 8b [2] 76 89 [2] 31 98 [2] 7f 94 [2] 73 9e [2] 64 95 [2] 7f db [2] 42 }

  condition:
    any of them
}