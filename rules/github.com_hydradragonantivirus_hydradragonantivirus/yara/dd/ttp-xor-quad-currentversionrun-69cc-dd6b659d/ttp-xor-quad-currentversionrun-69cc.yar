rule TTP_XOR_QUAD_CurrentVersionRun_69cc {
  strings:
    $key_69cc = { 3a a3 [2] 1e ad [2] 35 81 [2] 1b a3 [2] 0f b8 [2] 00 a2 [2] 1e bf [2] 1c be [2] 07 b8 [2] 1b bf [2] 07 90 }

  condition:
    any of them
}