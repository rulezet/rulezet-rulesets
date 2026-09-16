rule TTP_XOR_QUAD_CurrentVersionRun_e32a {
  strings:
    $key_e32a = { b0 45 [2] 94 4b [2] bf 67 [2] 91 45 [2] 85 5e [2] 8a 44 [2] 94 59 [2] 96 58 [2] 8d 5e [2] 91 59 [2] 8d 76 }

  condition:
    any of them
}