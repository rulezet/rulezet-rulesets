rule TTP_XOR_QUAD_CurrentVersionRun_e94b {
  strings:
    $key_e94b = { ba 24 [2] 9e 2a [2] b5 06 [2] 9b 24 [2] 8f 3f [2] 80 25 [2] 9e 38 [2] 9c 39 [2] 87 3f [2] 9b 38 [2] 87 17 }

  condition:
    any of them
}