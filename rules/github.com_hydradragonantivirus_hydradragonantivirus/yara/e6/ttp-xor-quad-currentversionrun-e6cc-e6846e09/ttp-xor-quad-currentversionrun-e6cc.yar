rule TTP_XOR_QUAD_CurrentVersionRun_e6cc {
  strings:
    $key_e6cc = { b5 a3 [2] 91 ad [2] ba 81 [2] 94 a3 [2] 80 b8 [2] 8f a2 [2] 91 bf [2] 93 be [2] 88 b8 [2] 94 bf [2] 88 90 }

  condition:
    any of them
}