rule TTP_XOR_MULT_DOSStub_37bf {
  strings:
    $key_37bf = { 63 d7 [2] 17 cf [2] 50 cd [2] 17 dc [2] 59 d0 [2] 55 da [2] 42 d1 [2] 59 9f [2] 64 }

  condition:
    any of them
}