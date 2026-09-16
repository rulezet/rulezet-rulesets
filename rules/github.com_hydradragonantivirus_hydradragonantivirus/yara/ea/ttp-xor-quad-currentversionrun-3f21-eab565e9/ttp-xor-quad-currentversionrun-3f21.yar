rule TTP_XOR_QUAD_CurrentVersionRun_3f21 {
  strings:
    $key_3f21 = { 6c 4e [2] 48 40 [2] 63 6c [2] 4d 4e [2] 59 55 [2] 56 4f [2] 48 52 [2] 4a 53 [2] 51 55 [2] 4d 52 [2] 51 7d }

  condition:
    any of them
}