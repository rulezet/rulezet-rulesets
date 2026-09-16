rule TTP_XOR_QUAD_CurrentVersionRun_c132 {
  strings:
    $key_c132 = { 92 5d [2] b6 53 [2] 9d 7f [2] b3 5d [2] a7 46 [2] a8 5c [2] b6 41 [2] b4 40 [2] af 46 [2] b3 41 [2] af 6e }

  condition:
    any of them
}