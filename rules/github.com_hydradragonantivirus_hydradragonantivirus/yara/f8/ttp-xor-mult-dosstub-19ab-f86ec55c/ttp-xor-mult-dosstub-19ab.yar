rule TTP_XOR_MULT_DOSStub_19ab {
  strings:
    $key_19ab = { 4d c3 [2] 39 db [2] 7e d9 [2] 39 c8 [2] 77 c4 [2] 7b ce [2] 6c c5 [2] 77 8b [2] 4a }

  condition:
    any of them
}