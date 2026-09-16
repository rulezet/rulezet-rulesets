rule TTP_XOR_QUAD_CurrentVersionRun_f36a {
  strings:
    $key_f36a = { a0 05 [2] 84 0b [2] af 27 [2] 81 05 [2] 95 1e [2] 9a 04 [2] 84 19 [2] 86 18 [2] 9d 1e [2] 81 19 [2] 9d 36 }

  condition:
    any of them
}