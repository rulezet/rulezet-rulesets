rule TTP_XOR_QUAD_CurrentVersionRun_2cb2 {
  strings:
    $key_2cb2 = { 7f dd [2] 5b d3 [2] 70 ff [2] 5e dd [2] 4a c6 [2] 45 dc [2] 5b c1 [2] 59 c0 [2] 42 c6 [2] 5e c1 [2] 42 ee }

  condition:
    any of them
}