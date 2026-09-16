rule TTP_XOR_MULT_DOSStub_bbab {
  strings:
    $key_bbab = { ef c3 [2] 9b db [2] dc d9 [2] 9b c8 [2] d5 c4 [2] d9 ce [2] ce c5 [2] d5 8b [2] e8 }

  condition:
    any of them
}