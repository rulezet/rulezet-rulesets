rule TTP_XOR_QUAD_CurrentVersionRun_6321 {
  strings:
    $key_6321 = { 30 4e [2] 14 40 [2] 3f 6c [2] 11 4e [2] 05 55 [2] 0a 4f [2] 14 52 [2] 16 53 [2] 0d 55 [2] 11 52 [2] 0d 7d }

  condition:
    any of them
}