rule TTP_XOR_QUAD_CurrentVersionRun_50cc {
  strings:
    $key_50cc = { 03 a3 [2] 27 ad [2] 0c 81 [2] 22 a3 [2] 36 b8 [2] 39 a2 [2] 27 bf [2] 25 be [2] 3e b8 [2] 22 bf [2] 3e 90 }

  condition:
    any of them
}