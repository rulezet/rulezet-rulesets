rule TTP_XOR_QUAD_CurrentVersionRun_9eda {
  strings:
    $key_9eda = { cd b5 [2] e9 bb [2] c2 97 [2] ec b5 [2] f8 ae [2] f7 b4 [2] e9 a9 [2] eb a8 [2] f0 ae [2] ec a9 [2] f0 86 }

  condition:
    any of them
}