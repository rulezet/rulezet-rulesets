rule TTP_XOR_QUAD_CurrentVersionRun_3ac6 {
  strings:
    $key_3ac6 = { 69 a9 [2] 4d a7 [2] 66 8b [2] 48 a9 [2] 5c b2 [2] 53 a8 [2] 4d b5 [2] 4f b4 [2] 54 b2 [2] 48 b5 [2] 54 9a }

  condition:
    any of them
}