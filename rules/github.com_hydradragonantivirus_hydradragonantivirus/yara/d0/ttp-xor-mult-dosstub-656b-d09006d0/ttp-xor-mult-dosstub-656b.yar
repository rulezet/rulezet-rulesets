rule TTP_XOR_MULT_DOSStub_656b {
  strings:
    $key_656b = { 31 03 [2] 45 1b [2] 02 19 [2] 45 08 [2] 0b 04 [2] 07 0e [2] 10 05 [2] 0b 4b [2] 36 }

  condition:
    any of them
}