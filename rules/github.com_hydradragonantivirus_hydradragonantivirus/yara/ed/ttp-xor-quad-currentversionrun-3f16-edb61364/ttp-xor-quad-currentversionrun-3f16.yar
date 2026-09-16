rule TTP_XOR_QUAD_CurrentVersionRun_3f16 {
  strings:
    $key_3f16 = { 6c 79 [2] 48 77 [2] 63 5b [2] 4d 79 [2] 59 62 [2] 56 78 [2] 48 65 [2] 4a 64 [2] 51 62 [2] 4d 65 [2] 51 4a }

  condition:
    any of them
}