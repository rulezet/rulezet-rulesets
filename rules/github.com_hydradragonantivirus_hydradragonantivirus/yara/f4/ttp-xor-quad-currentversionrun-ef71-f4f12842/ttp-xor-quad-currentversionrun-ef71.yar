rule TTP_XOR_QUAD_CurrentVersionRun_ef71 {
  strings:
    $key_ef71 = { bc 1e [2] 98 10 [2] b3 3c [2] 9d 1e [2] 89 05 [2] 86 1f [2] 98 02 [2] 9a 03 [2] 81 05 [2] 9d 02 [2] 81 2d }

  condition:
    any of them
}