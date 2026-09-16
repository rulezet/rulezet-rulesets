rule TTP_XOR_MULT_DOSStub_ed9b {
  strings:
    $key_ed9b = { b9 f3 [2] cd eb [2] 8a e9 [2] cd f8 [2] 83 f4 [2] 8f fe [2] 98 f5 [2] 83 bb [2] be }

  condition:
    any of them
}