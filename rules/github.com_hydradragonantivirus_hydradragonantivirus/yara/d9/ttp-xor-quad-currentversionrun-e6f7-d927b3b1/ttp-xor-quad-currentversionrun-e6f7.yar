rule TTP_XOR_QUAD_CurrentVersionRun_e6f7 {
  strings:
    $key_e6f7 = { b5 98 [2] 91 96 [2] ba ba [2] 94 98 [2] 80 83 [2] 8f 99 [2] 91 84 [2] 93 85 [2] 88 83 [2] 94 84 [2] 88 ab }

  condition:
    any of them
}