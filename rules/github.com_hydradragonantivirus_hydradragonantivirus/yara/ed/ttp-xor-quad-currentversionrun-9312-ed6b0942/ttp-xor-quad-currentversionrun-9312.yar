rule TTP_XOR_QUAD_CurrentVersionRun_9312 {
  strings:
    $key_9312 = { c0 7d [2] e4 73 [2] cf 5f [2] e1 7d [2] f5 66 [2] fa 7c [2] e4 61 [2] e6 60 [2] fd 66 [2] e1 61 [2] fd 4e }

  condition:
    any of them
}