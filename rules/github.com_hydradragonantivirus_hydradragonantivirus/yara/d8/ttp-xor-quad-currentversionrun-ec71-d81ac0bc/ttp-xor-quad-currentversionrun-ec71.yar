rule TTP_XOR_QUAD_CurrentVersionRun_ec71 {
  strings:
    $key_ec71 = { bf 1e [2] 9b 10 [2] b0 3c [2] 9e 1e [2] 8a 05 [2] 85 1f [2] 9b 02 [2] 99 03 [2] 82 05 [2] 9e 02 [2] 82 2d }

  condition:
    any of them
}