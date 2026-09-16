rule TTP_XOR_QUAD_CurrentVersionRun_db88 {
  strings:
    $key_db88 = { 88 e7 [2] ac e9 [2] 87 c5 [2] a9 e7 [2] bd fc [2] b2 e6 [2] ac fb [2] ae fa [2] b5 fc [2] a9 fb [2] b5 d4 }

  condition:
    any of them
}