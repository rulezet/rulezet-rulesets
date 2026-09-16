rule TTP_XOR_MULT_DOSStub_eded {
  strings:
    $key_eded = { b9 85 [2] cd 9d [2] 8a 9f [2] cd 8e [2] 83 82 [2] 8f 88 [2] 98 83 [2] 83 cd [2] be }

  condition:
    any of them
}