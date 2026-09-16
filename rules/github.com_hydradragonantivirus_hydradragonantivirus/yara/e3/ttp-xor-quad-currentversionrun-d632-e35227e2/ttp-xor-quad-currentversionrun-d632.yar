rule TTP_XOR_QUAD_CurrentVersionRun_d632 {
  strings:
    $key_d632 = { 85 5d [2] a1 53 [2] 8a 7f [2] a4 5d [2] b0 46 [2] bf 5c [2] a1 41 [2] a3 40 [2] b8 46 [2] a4 41 [2] b8 6e }

  condition:
    any of them
}