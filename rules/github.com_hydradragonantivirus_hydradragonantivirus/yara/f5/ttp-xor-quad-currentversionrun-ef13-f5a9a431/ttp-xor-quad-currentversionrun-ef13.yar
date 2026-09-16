rule TTP_XOR_QUAD_CurrentVersionRun_ef13 {
  strings:
    $key_ef13 = { bc 7c [2] 98 72 [2] b3 5e [2] 9d 7c [2] 89 67 [2] 86 7d [2] 98 60 [2] 9a 61 [2] 81 67 [2] 9d 60 [2] 81 4f }

  condition:
    any of them
}