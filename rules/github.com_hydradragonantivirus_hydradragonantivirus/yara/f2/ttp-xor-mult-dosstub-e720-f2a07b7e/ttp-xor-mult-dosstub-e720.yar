rule TTP_XOR_MULT_DOSStub_e720 {
  strings:
    $key_e720 = { b3 48 [2] c7 50 [2] 80 52 [2] c7 43 [2] 89 4f [2] 85 45 [2] 92 4e [2] 89 00 [2] b4 }

  condition:
    any of them
}