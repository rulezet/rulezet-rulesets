rule TTP_XOR_QUAD_CurrentVersionRun_f32c {
  strings:
    $key_f32c = { a0 43 [2] 84 4d [2] af 61 [2] 81 43 [2] 95 58 [2] 9a 42 [2] 84 5f [2] 86 5e [2] 9d 58 [2] 81 5f [2] 9d 70 }

  condition:
    any of them
}