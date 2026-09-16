rule TTP_XOR_QUAD_CurrentVersionRun_0a21 {
  strings:
    $key_0a21 = { 59 4e [2] 7d 40 [2] 56 6c [2] 78 4e [2] 6c 55 [2] 63 4f [2] 7d 52 [2] 7f 53 [2] 64 55 [2] 78 52 [2] 64 7d }

  condition:
    any of them
}