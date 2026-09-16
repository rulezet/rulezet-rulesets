rule TTP_XOR_QUAD_CurrentVersionRun_0306 {
  strings:
    $key_0306 = { 50 69 [2] 74 67 [2] 5f 4b [2] 71 69 [2] 65 72 [2] 6a 68 [2] 74 75 [2] 76 74 [2] 6d 72 [2] 71 75 [2] 6d 5a }

  condition:
    any of them
}