rule TTP_XOR_MULT_DOSStub_2ebf {
  strings:
    $key_2ebf = { 7a d7 [2] 0e cf [2] 49 cd [2] 0e dc [2] 40 d0 [2] 4c da [2] 5b d1 [2] 40 9f [2] 7d }

  condition:
    any of them
}