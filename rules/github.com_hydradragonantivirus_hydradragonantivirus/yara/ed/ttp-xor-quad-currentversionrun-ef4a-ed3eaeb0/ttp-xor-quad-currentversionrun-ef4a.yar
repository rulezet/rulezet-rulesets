rule TTP_XOR_QUAD_CurrentVersionRun_ef4a {
  strings:
    $key_ef4a = { bc 25 [2] 98 2b [2] b3 07 [2] 9d 25 [2] 89 3e [2] 86 24 [2] 98 39 [2] 9a 38 [2] 81 3e [2] 9d 39 [2] 81 16 }

  condition:
    any of them
}