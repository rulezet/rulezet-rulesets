rule TTP_XOR_QUAD_CurrentVersionRun_e651 {
  strings:
    $key_e651 = { b5 3e [2] 91 30 [2] ba 1c [2] 94 3e [2] 80 25 [2] 8f 3f [2] 91 22 [2] 93 23 [2] 88 25 [2] 94 22 [2] 88 0d }

  condition:
    any of them
}