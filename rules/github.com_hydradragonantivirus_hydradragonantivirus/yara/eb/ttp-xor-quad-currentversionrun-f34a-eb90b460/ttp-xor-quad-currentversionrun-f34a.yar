rule TTP_XOR_QUAD_CurrentVersionRun_f34a {
  strings:
    $key_f34a = { a0 25 [2] 84 2b [2] af 07 [2] 81 25 [2] 95 3e [2] 9a 24 [2] 84 39 [2] 86 38 [2] 9d 3e [2] 81 39 [2] 9d 16 }

  condition:
    any of them
}