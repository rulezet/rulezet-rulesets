rule TTP_XOR_QUAD_CurrentVersionRun_0a51 {
  strings:
    $key_0a51 = { 59 3e [2] 7d 30 [2] 56 1c [2] 78 3e [2] 6c 25 [2] 63 3f [2] 7d 22 [2] 7f 23 [2] 64 25 [2] 78 22 [2] 64 0d }

  condition:
    any of them
}