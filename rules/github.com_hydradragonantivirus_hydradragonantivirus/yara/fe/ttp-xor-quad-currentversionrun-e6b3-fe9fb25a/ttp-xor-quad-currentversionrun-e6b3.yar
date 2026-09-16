rule TTP_XOR_QUAD_CurrentVersionRun_e6b3 {
  strings:
    $key_e6b3 = { b5 dc [2] 91 d2 [2] ba fe [2] 94 dc [2] 80 c7 [2] 8f dd [2] 91 c0 [2] 93 c1 [2] 88 c7 [2] 94 c0 [2] 88 ef }

  condition:
    any of them
}