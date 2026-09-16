rule TTP_XOR_MULT_DOSStub_6cbf {
  strings:
    $key_6cbf = { 38 d7 [2] 4c cf [2] 0b cd [2] 4c dc [2] 02 d0 [2] 0e da [2] 19 d1 [2] 02 9f [2] 3f }

  condition:
    any of them
}