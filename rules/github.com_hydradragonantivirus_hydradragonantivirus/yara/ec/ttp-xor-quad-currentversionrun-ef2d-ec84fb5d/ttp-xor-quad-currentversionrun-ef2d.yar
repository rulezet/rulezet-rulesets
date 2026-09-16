rule TTP_XOR_QUAD_CurrentVersionRun_ef2d {
  strings:
    $key_ef2d = { bc 42 [2] 98 4c [2] b3 60 [2] 9d 42 [2] 89 59 [2] 86 43 [2] 98 5e [2] 9a 5f [2] 81 59 [2] 9d 5e [2] 81 71 }

  condition:
    any of them
}