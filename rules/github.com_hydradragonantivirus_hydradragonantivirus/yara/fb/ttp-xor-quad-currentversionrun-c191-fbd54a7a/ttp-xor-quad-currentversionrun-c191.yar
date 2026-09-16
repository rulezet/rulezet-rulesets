rule TTP_XOR_QUAD_CurrentVersionRun_c191 {
  strings:
    $key_c191 = { 92 fe [2] b6 f0 [2] 9d dc [2] b3 fe [2] a7 e5 [2] a8 ff [2] b6 e2 [2] b4 e3 [2] af e5 [2] b3 e2 [2] af cd }

  condition:
    any of them
}