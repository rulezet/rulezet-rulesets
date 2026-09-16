rule TTP_XOR_MULT_DOSStub_0226 {
  strings:
    $key_0226 = { 56 4e [2] 22 56 [2] 65 54 [2] 22 45 [2] 6c 49 [2] 60 43 [2] 77 48 [2] 6c 06 [2] 51 }

  condition:
    any of them
}