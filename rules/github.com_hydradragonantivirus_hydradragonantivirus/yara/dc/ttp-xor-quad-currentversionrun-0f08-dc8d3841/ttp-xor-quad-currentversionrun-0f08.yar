rule TTP_XOR_QUAD_CurrentVersionRun_0f08 {
  strings:
    $key_0f08 = { 5c 67 [2] 78 69 [2] 53 45 [2] 7d 67 [2] 69 7c [2] 66 66 [2] 78 7b [2] 7a 7a [2] 61 7c [2] 7d 7b [2] 61 54 }

  condition:
    any of them
}