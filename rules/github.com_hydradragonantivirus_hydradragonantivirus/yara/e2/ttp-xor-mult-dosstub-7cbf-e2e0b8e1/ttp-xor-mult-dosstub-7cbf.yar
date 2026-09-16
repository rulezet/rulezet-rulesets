rule TTP_XOR_MULT_DOSStub_7cbf {
  strings:
    $key_7cbf = { 28 d7 [2] 5c cf [2] 1b cd [2] 5c dc [2] 12 d0 [2] 1e da [2] 09 d1 [2] 12 9f [2] 2f }

  condition:
    any of them
}