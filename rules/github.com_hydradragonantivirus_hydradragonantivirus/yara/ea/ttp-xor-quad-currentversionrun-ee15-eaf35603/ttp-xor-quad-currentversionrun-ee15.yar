rule TTP_XOR_QUAD_CurrentVersionRun_ee15 {
  strings:
    $key_ee15 = { bd 7a [2] 99 74 [2] b2 58 [2] 9c 7a [2] 88 61 [2] 87 7b [2] 99 66 [2] 9b 67 [2] 80 61 [2] 9c 66 [2] 80 49 }

  condition:
    any of them
}