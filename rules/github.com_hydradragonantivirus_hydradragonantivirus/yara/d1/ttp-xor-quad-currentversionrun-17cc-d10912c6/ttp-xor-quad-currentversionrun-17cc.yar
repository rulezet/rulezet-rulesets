rule TTP_XOR_QUAD_CurrentVersionRun_17cc {
  strings:
    $key_17cc = { 44 a3 [2] 60 ad [2] 4b 81 [2] 65 a3 [2] 71 b8 [2] 7e a2 [2] 60 bf [2] 62 be [2] 79 b8 [2] 65 bf [2] 79 90 }

  condition:
    any of them
}