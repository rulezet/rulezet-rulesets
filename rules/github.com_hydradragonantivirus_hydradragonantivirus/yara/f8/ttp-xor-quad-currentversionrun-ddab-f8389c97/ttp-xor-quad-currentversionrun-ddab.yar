rule TTP_XOR_QUAD_CurrentVersionRun_ddab {
  strings:
    $key_ddab = { 8e c4 [2] aa ca [2] 81 e6 [2] af c4 [2] bb df [2] b4 c5 [2] aa d8 [2] a8 d9 [2] b3 df [2] af d8 [2] b3 f7 }

  condition:
    any of them
}