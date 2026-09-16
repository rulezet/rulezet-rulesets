rule TTP_XOR_QUAD_CurrentVersionRun_c9a3 {
  strings:
    $key_c9a3 = { 9a cc [2] be c2 [2] 95 ee [2] bb cc [2] af d7 [2] a0 cd [2] be d0 [2] bc d1 [2] a7 d7 [2] bb d0 [2] a7 ff }

  condition:
    any of them
}