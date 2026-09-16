rule TTP_XOR_QUAD_CurrentVersionRun_3fe0 {
  strings:
    $key_3fe0 = { 6c 8f [2] 48 81 [2] 63 ad [2] 4d 8f [2] 59 94 [2] 56 8e [2] 48 93 [2] 4a 92 [2] 51 94 [2] 4d 93 [2] 51 bc }

  condition:
    any of them
}