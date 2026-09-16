rule TTP_XOR_QUAD_CurrentVersionRun_3749 {
  strings:
    $key_3749 = { 64 26 [2] 40 28 [2] 6b 04 [2] 45 26 [2] 51 3d [2] 5e 27 [2] 40 3a [2] 42 3b [2] 59 3d [2] 45 3a [2] 59 15 }

  condition:
    any of them
}