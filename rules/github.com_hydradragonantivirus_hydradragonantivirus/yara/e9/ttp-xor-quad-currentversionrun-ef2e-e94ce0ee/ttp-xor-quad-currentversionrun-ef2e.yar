rule TTP_XOR_QUAD_CurrentVersionRun_ef2e {
  strings:
    $key_ef2e = { bc 41 [2] 98 4f [2] b3 63 [2] 9d 41 [2] 89 5a [2] 86 40 [2] 98 5d [2] 9a 5c [2] 81 5a [2] 9d 5d [2] 81 72 }

  condition:
    any of them
}