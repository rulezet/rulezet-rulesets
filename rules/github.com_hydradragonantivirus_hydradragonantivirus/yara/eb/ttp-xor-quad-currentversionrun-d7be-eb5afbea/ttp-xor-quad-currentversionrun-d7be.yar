rule TTP_XOR_QUAD_CurrentVersionRun_d7be {
  strings:
    $key_d7be = { 84 d1 [2] a0 df [2] 8b f3 [2] a5 d1 [2] b1 ca [2] be d0 [2] a0 cd [2] a2 cc [2] b9 ca [2] a5 cd [2] b9 e2 }

  condition:
    any of them
}