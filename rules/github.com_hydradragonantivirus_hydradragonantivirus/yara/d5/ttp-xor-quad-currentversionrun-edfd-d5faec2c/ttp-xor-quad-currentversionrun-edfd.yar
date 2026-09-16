rule TTP_XOR_QUAD_CurrentVersionRun_edfd {
  strings:
    $key_edfd = { be 92 [2] 9a 9c [2] b1 b0 [2] 9f 92 [2] 8b 89 [2] 84 93 [2] 9a 8e [2] 98 8f [2] 83 89 [2] 9f 8e [2] 83 a1 }

  condition:
    any of them
}