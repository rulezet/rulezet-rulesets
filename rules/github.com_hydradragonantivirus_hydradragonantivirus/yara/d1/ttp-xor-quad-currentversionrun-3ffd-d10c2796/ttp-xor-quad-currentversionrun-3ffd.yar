rule TTP_XOR_QUAD_CurrentVersionRun_3ffd {
  strings:
    $key_3ffd = { 6c 92 [2] 48 9c [2] 63 b0 [2] 4d 92 [2] 59 89 [2] 56 93 [2] 48 8e [2] 4a 8f [2] 51 89 [2] 4d 8e [2] 51 a1 }

  condition:
    any of them
}