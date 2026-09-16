rule TTP_XOR_MULT_DOSStub_067b {
  strings:
    $key_067b = { 52 13 [2] 26 0b [2] 61 09 [2] 26 18 [2] 68 14 [2] 64 1e [2] 73 15 [2] 68 5b [2] 55 }

  condition:
    any of them
}