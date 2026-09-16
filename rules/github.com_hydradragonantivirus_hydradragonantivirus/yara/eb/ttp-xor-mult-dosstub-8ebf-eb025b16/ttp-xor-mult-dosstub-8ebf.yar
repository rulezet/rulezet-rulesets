rule TTP_XOR_MULT_DOSStub_8ebf {
  strings:
    $key_8ebf = { da d7 [2] ae cf [2] e9 cd [2] ae dc [2] e0 d0 [2] ec da [2] fb d1 [2] e0 9f [2] dd }

  condition:
    any of them
}