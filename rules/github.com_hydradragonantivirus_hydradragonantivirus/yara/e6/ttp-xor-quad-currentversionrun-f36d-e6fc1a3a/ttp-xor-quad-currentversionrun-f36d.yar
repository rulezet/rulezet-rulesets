rule TTP_XOR_QUAD_CurrentVersionRun_f36d {
  strings:
    $key_f36d = { a0 02 [2] 84 0c [2] af 20 [2] 81 02 [2] 95 19 [2] 9a 03 [2] 84 1e [2] 86 1f [2] 9d 19 [2] 81 1e [2] 9d 31 }

  condition:
    any of them
}