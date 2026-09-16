rule TTP_XOR_QUAD_CurrentVersionRun_9dd9 {
  strings:
    $key_9dd9 = { ce b6 [2] ea b8 [2] c1 94 [2] ef b6 [2] fb ad [2] f4 b7 [2] ea aa [2] e8 ab [2] f3 ad [2] ef aa [2] f3 85 }

  condition:
    any of them
}