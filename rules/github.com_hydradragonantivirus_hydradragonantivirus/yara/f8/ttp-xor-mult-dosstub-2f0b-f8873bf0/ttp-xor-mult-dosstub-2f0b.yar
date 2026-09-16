rule TTP_XOR_MULT_DOSStub_2f0b {
  strings:
    $key_2f0b = { 7b 63 [2] 0f 7b [2] 48 79 [2] 0f 68 [2] 41 64 [2] 4d 6e [2] 5a 65 [2] 41 2b [2] 7c }

  condition:
    any of them
}