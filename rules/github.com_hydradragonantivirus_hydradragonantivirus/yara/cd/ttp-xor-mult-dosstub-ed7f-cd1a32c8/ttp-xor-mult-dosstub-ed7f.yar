rule TTP_XOR_MULT_DOSStub_ed7f {
  strings:
    $key_ed7f = { b9 17 [2] cd 0f [2] 8a 0d [2] cd 1c [2] 83 10 [2] 8f 1a [2] 98 11 [2] 83 5f [2] be }

  condition:
    any of them
}