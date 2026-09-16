rule TTP_XOR_MULT_DOSStub_0abf {
  strings:
    $key_0abf = { 5e d7 [2] 2a cf [2] 6d cd [2] 2a dc [2] 64 d0 [2] 68 da [2] 7f d1 [2] 64 9f [2] 59 }

  condition:
    any of them
}