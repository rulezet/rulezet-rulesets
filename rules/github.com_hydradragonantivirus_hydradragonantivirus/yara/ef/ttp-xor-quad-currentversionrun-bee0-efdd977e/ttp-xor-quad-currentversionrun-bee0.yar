rule TTP_XOR_QUAD_CurrentVersionRun_bee0 {
  strings:
    $key_bee0 = { ed 8f [2] c9 81 [2] e2 ad [2] cc 8f [2] d8 94 [2] d7 8e [2] c9 93 [2] cb 92 [2] d0 94 [2] cc 93 [2] d0 bc }

  condition:
    any of them
}