rule TTP_XOR_QUAD_CurrentVersionRun_0a06 {
  strings:
    $key_0a06 = { 59 69 [2] 7d 67 [2] 56 4b [2] 78 69 [2] 6c 72 [2] 63 68 [2] 7d 75 [2] 7f 74 [2] 64 72 [2] 78 75 [2] 64 5a }

  condition:
    any of them
}