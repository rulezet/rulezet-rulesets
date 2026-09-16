rule TTP_XOR_QUAD_CurrentVersionRun_79cc {
  strings:
    $key_79cc = { 2a a3 [2] 0e ad [2] 25 81 [2] 0b a3 [2] 1f b8 [2] 10 a2 [2] 0e bf [2] 0c be [2] 17 b8 [2] 0b bf [2] 17 90 }

  condition:
    any of them
}