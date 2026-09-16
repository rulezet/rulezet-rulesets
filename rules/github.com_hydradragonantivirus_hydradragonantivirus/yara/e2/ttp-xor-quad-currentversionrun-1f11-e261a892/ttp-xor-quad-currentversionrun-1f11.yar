rule TTP_XOR_QUAD_CurrentVersionRun_1f11 {
  strings:
    $key_1f11 = { 4c 7e [2] 68 70 [2] 43 5c [2] 6d 7e [2] 79 65 [2] 76 7f [2] 68 62 [2] 6a 63 [2] 71 65 [2] 6d 62 [2] 71 4d }

  condition:
    any of them
}