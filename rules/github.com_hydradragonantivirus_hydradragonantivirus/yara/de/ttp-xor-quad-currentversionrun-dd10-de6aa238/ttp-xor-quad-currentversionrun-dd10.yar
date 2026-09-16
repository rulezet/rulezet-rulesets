rule TTP_XOR_QUAD_CurrentVersionRun_dd10 {
  strings:
    $key_dd10 = { 8e 7f [2] aa 71 [2] 81 5d [2] af 7f [2] bb 64 [2] b4 7e [2] aa 63 [2] a8 62 [2] b3 64 [2] af 63 [2] b3 4c }

  condition:
    any of them
}