rule TTP_XOR_QUAD_CurrentVersionRun_fdf0 {
  strings:
    $key_fdf0 = { ae 9f [2] 8a 91 [2] a1 bd [2] 8f 9f [2] 9b 84 [2] 94 9e [2] 8a 83 [2] 88 82 [2] 93 84 [2] 8f 83 [2] 93 ac }

  condition:
    any of them
}