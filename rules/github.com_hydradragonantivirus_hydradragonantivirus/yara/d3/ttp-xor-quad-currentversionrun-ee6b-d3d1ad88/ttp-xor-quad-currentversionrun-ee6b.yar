rule TTP_XOR_QUAD_CurrentVersionRun_ee6b {
  strings:
    $key_ee6b = { bd 04 [2] 99 0a [2] b2 26 [2] 9c 04 [2] 88 1f [2] 87 05 [2] 99 18 [2] 9b 19 [2] 80 1f [2] 9c 18 [2] 80 37 }

  condition:
    any of them
}