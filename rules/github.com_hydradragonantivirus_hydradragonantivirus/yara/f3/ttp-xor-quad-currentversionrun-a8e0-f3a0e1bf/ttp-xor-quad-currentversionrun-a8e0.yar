rule TTP_XOR_QUAD_CurrentVersionRun_a8e0 {
  strings:
    $key_a8e0 = { fb 8f [2] df 81 [2] f4 ad [2] da 8f [2] ce 94 [2] c1 8e [2] df 93 [2] dd 92 [2] c6 94 [2] da 93 [2] c6 bc }

  condition:
    any of them
}