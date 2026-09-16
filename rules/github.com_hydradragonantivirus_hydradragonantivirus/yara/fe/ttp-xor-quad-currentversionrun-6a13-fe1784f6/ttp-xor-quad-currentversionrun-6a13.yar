rule TTP_XOR_QUAD_CurrentVersionRun_6a13 {
  strings:
    $key_6a13 = { 39 7c [2] 1d 72 [2] 36 5e [2] 18 7c [2] 0c 67 [2] 03 7d [2] 1d 60 [2] 1f 61 [2] 04 67 [2] 18 60 [2] 04 4f }

  condition:
    any of them
}