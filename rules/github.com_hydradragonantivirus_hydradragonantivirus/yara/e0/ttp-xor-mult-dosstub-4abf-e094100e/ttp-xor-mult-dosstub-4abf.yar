rule TTP_XOR_MULT_DOSStub_4abf {
  strings:
    $key_4abf = { 1e d7 [2] 6a cf [2] 2d cd [2] 6a dc [2] 24 d0 [2] 28 da [2] 3f d1 [2] 24 9f [2] 19 }

  condition:
    any of them
}