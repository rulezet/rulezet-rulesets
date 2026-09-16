rule TTP_XOR_MULT_DOSStub_edcb {
  strings:
    $key_edcb = { b9 a3 [2] cd bb [2] 8a b9 [2] cd a8 [2] 83 a4 [2] 8f ae [2] 98 a5 [2] 83 eb [2] be }

  condition:
    any of them
}