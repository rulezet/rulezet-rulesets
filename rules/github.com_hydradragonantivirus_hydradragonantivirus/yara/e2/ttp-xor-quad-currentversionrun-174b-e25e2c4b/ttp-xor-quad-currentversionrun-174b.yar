rule TTP_XOR_QUAD_CurrentVersionRun_174b {
  strings:
    $key_174b = { 44 24 [2] 60 2a [2] 4b 06 [2] 65 24 [2] 71 3f [2] 7e 25 [2] 60 38 [2] 62 39 [2] 79 3f [2] 65 38 [2] 79 17 }

  condition:
    any of them
}