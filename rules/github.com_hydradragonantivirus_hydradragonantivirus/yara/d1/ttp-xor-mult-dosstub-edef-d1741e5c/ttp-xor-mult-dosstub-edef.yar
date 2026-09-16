rule TTP_XOR_MULT_DOSStub_edef {
  strings:
    $key_edef = { b9 87 [2] cd 9f [2] 8a 9d [2] cd 8c [2] 83 80 [2] 8f 8a [2] 98 81 [2] 83 cf [2] be }

  condition:
    any of them
}