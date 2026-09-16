rule TTP_XOR_QUAD_CurrentVersionRun_f32a {
  strings:
    $key_f32a = { a0 45 [2] 84 4b [2] af 67 [2] 81 45 [2] 95 5e [2] 9a 44 [2] 84 59 [2] 86 58 [2] 9d 5e [2] 81 59 [2] 9d 76 }

  condition:
    any of them
}