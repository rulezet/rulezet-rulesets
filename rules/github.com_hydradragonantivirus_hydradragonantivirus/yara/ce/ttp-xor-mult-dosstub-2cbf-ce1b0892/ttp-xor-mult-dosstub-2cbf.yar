rule TTP_XOR_MULT_DOSStub_2cbf {
  strings:
    $key_2cbf = { 78 d7 [2] 0c cf [2] 4b cd [2] 0c dc [2] 42 d0 [2] 4e da [2] 59 d1 [2] 42 9f [2] 7f }

  condition:
    any of them
}