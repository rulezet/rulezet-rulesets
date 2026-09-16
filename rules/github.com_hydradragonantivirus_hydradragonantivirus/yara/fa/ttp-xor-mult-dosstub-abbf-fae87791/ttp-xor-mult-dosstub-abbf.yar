rule TTP_XOR_MULT_DOSStub_abbf {
  strings:
    $key_abbf = { ff d7 [2] 8b cf [2] cc cd [2] 8b dc [2] c5 d0 [2] c9 da [2] de d1 [2] c5 9f [2] f8 }

  condition:
    any of them
}