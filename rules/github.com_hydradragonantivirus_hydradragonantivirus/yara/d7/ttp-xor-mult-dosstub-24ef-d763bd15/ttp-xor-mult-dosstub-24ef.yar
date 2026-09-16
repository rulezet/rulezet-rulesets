rule TTP_XOR_MULT_DOSStub_24ef {
  strings:
    $key_24ef = { 70 87 [2] 04 9f [2] 43 9d [2] 04 8c [2] 4a 80 [2] 46 8a [2] 51 81 [2] 4a cf [2] 77 }

  condition:
    any of them
}