rule TTP_XOR_QUAD_CurrentVersionRun_3f36 {
  strings:
    $key_3f36 = { 6c 59 [2] 48 57 [2] 63 7b [2] 4d 59 [2] 59 42 [2] 56 58 [2] 48 45 [2] 4a 44 [2] 51 42 [2] 4d 45 [2] 51 6a }

  condition:
    any of them
}