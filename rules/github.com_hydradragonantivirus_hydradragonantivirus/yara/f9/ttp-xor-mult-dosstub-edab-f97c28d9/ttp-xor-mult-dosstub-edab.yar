rule TTP_XOR_MULT_DOSStub_edab {
  strings:
    $key_edab = { b9 c3 [2] cd db [2] 8a d9 [2] cd c8 [2] 83 c4 [2] 8f ce [2] 98 c5 [2] 83 8b [2] be }

  condition:
    any of them
}