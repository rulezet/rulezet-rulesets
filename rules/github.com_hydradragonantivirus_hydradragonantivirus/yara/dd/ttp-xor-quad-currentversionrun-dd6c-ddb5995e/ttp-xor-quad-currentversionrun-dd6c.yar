rule TTP_XOR_QUAD_CurrentVersionRun_dd6c {
  strings:
    $key_dd6c = { 8e 03 [2] aa 0d [2] 81 21 [2] af 03 [2] bb 18 [2] b4 02 [2] aa 1f [2] a8 1e [2] b3 18 [2] af 1f [2] b3 30 }

  condition:
    any of them
}