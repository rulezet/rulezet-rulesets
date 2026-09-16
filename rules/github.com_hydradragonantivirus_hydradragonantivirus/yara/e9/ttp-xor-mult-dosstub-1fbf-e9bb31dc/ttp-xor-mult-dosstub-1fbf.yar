rule TTP_XOR_MULT_DOSStub_1fbf {
  strings:
    $key_1fbf = { 4b d7 [2] 3f cf [2] 78 cd [2] 3f dc [2] 71 d0 [2] 7d da [2] 6a d1 [2] 71 9f [2] 4c }

  condition:
    any of them
}