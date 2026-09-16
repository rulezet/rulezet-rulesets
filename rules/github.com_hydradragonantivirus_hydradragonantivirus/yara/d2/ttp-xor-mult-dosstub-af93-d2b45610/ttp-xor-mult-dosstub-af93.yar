rule TTP_XOR_MULT_DOSStub_af93 {
  strings:
    $key_af93 = { fb fb [2] 8f e3 [2] c8 e1 [2] 8f f0 [2] c1 fc [2] cd f6 [2] da fd [2] c1 b3 [2] fc }

  condition:
    any of them
}