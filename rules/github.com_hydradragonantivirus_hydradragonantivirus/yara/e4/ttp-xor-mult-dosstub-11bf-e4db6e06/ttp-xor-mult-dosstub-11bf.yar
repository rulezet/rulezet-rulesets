rule TTP_XOR_MULT_DOSStub_11bf {
  strings:
    $key_11bf = { 45 d7 [2] 31 cf [2] 76 cd [2] 31 dc [2] 7f d0 [2] 73 da [2] 64 d1 [2] 7f 9f [2] 42 }

  condition:
    any of them
}