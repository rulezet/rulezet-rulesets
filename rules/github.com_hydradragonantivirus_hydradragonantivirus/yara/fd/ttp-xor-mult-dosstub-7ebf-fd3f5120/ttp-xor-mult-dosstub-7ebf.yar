rule TTP_XOR_MULT_DOSStub_7ebf {
  strings:
    $key_7ebf = { 2a d7 [2] 5e cf [2] 19 cd [2] 5e dc [2] 10 d0 [2] 1c da [2] 0b d1 [2] 10 9f [2] 2d }

  condition:
    any of them
}