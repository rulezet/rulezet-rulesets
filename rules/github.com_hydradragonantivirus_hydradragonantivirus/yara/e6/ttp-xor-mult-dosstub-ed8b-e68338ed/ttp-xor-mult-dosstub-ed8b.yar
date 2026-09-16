rule TTP_XOR_MULT_DOSStub_ed8b {
  strings:
    $key_ed8b = { b9 e3 [2] cd fb [2] 8a f9 [2] cd e8 [2] 83 e4 [2] 8f ee [2] 98 e5 [2] 83 ab [2] be }

  condition:
    any of them
}