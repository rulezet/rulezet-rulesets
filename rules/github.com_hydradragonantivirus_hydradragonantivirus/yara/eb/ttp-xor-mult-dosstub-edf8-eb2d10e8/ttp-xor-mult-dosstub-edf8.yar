rule TTP_XOR_MULT_DOSStub_edf8 {
  strings:
    $key_edf8 = { b9 90 [2] cd 88 [2] 8a 8a [2] cd 9b [2] 83 97 [2] 8f 9d [2] 98 96 [2] 83 d8 [2] be }

  condition:
    any of them
}