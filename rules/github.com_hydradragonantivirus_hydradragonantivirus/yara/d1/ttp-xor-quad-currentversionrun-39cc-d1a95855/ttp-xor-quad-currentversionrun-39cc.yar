rule TTP_XOR_QUAD_CurrentVersionRun_39cc {
  strings:
    $key_39cc = { 6a a3 [2] 4e ad [2] 65 81 [2] 4b a3 [2] 5f b8 [2] 50 a2 [2] 4e bf [2] 4c be [2] 57 b8 [2] 4b bf [2] 57 90 }

  condition:
    any of them
}