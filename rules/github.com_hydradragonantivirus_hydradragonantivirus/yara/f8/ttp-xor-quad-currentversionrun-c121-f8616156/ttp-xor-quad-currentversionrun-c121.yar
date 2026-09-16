rule TTP_XOR_QUAD_CurrentVersionRun_c121 {
  strings:
    $key_c121 = { 92 4e [2] b6 40 [2] 9d 6c [2] b3 4e [2] a7 55 [2] a8 4f [2] b6 52 [2] b4 53 [2] af 55 [2] b3 52 [2] af 7d }

  condition:
    any of them
}