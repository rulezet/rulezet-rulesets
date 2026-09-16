rule TTP_XOR_QUAD_CurrentVersionRun_2321 {
  strings:
    $key_2321 = { 70 4e [2] 54 40 [2] 7f 6c [2] 51 4e [2] 45 55 [2] 4a 4f [2] 54 52 [2] 56 53 [2] 4d 55 [2] 51 52 [2] 4d 7d }

  condition:
    any of them
}