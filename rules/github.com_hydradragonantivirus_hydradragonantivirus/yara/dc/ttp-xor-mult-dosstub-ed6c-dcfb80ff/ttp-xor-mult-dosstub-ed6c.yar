rule TTP_XOR_MULT_DOSStub_ed6c {
  strings:
    $key_ed6c = { b9 04 [2] cd 1c [2] 8a 1e [2] cd 0f [2] 83 03 [2] 8f 09 [2] 98 02 [2] 83 4c [2] be }

  condition:
    any of them
}