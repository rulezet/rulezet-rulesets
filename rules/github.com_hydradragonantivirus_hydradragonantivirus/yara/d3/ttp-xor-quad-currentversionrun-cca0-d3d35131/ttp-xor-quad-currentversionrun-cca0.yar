rule TTP_XOR_QUAD_CurrentVersionRun_cca0 {
  strings:
    $key_cca0 = { 9f cf [2] bb c1 [2] 90 ed [2] be cf [2] aa d4 [2] a5 ce [2] bb d3 [2] b9 d2 [2] a2 d4 [2] be d3 [2] a2 fc }

  condition:
    any of them
}