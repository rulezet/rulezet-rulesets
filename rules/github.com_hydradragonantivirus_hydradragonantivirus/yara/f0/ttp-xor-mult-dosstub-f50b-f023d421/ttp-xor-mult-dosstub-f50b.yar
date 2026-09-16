rule TTP_XOR_MULT_DOSStub_f50b {
  strings:
    $key_f50b = { a1 63 [2] d5 7b [2] 92 79 [2] d5 68 [2] 9b 64 [2] 97 6e [2] 80 65 [2] 9b 2b [2] a6 }

  condition:
    any of them
}