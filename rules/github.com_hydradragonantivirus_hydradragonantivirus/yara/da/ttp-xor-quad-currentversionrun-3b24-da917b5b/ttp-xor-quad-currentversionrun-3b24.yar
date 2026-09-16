rule TTP_XOR_QUAD_CurrentVersionRun_3b24 {
  strings:
    $key_3b24 = { 68 4b [2] 4c 45 [2] 67 69 [2] 49 4b [2] 5d 50 [2] 52 4a [2] 4c 57 [2] 4e 56 [2] 55 50 [2] 49 57 [2] 55 78 }

  condition:
    any of them
}