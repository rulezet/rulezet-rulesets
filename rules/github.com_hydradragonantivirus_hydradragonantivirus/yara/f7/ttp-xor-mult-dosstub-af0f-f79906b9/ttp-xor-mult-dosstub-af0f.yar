rule TTP_XOR_MULT_DOSStub_af0f {
  strings:
    $key_af0f = { fb 67 [2] 8f 7f [2] c8 7d [2] 8f 6c [2] c1 60 [2] cd 6a [2] da 61 [2] c1 2f [2] fc }

  condition:
    any of them
}