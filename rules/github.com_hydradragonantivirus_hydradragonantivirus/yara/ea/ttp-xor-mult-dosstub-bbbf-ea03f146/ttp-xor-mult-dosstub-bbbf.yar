rule TTP_XOR_MULT_DOSStub_bbbf {
  strings:
    $key_bbbf = { ef d7 [2] 9b cf [2] dc cd [2] 9b dc [2] d5 d0 [2] d9 da [2] ce d1 [2] d5 9f [2] e8 }

  condition:
    any of them
}