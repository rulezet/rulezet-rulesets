rule TTP_XOR_QUAD_CurrentVersionRun_cca3 {
  strings:
    $key_cca3 = { 9f cc [2] bb c2 [2] 90 ee [2] be cc [2] aa d7 [2] a5 cd [2] bb d0 [2] b9 d1 [2] a2 d7 [2] be d0 [2] a2 ff }

  condition:
    any of them
}