rule TTP_XOR_QUAD_CurrentVersionRun_e1d9 {
  strings:
    $key_e1d9 = { b2 b6 [2] 96 b8 [2] bd 94 [2] 93 b6 [2] 87 ad [2] 88 b7 [2] 96 aa [2] 94 ab [2] 8f ad [2] 93 aa [2] 8f 85 }

  condition:
    any of them
}