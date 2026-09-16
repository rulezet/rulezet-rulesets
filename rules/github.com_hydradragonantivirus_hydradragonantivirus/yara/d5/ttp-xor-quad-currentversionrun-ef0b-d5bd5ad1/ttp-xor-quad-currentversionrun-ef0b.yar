rule TTP_XOR_QUAD_CurrentVersionRun_ef0b {
  strings:
    $key_ef0b = { bc 64 [2] 98 6a [2] b3 46 [2] 9d 64 [2] 89 7f [2] 86 65 [2] 98 78 [2] 9a 79 [2] 81 7f [2] 9d 78 [2] 81 57 }

  condition:
    any of them
}