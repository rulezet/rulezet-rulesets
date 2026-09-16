rule TTP_XOR_MULT_DOSStub_ffbc {
  strings:
    $key_ffbc = { ab d4 [2] df cc [2] 98 ce [2] df df [2] 91 d3 [2] 9d d9 [2] 8a d2 [2] 91 9c [2] ac }

  condition:
    any of them
}