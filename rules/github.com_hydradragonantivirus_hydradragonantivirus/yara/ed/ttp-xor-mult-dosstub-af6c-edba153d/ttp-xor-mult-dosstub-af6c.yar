rule TTP_XOR_MULT_DOSStub_af6c {
  strings:
    $key_af6c = { fb 04 [2] 8f 1c [2] c8 1e [2] 8f 0f [2] c1 03 [2] cd 09 [2] da 02 [2] c1 4c [2] fc }

  condition:
    any of them
}