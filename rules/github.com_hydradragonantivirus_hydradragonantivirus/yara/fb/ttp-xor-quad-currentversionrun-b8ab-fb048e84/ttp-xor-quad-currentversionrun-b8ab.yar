rule TTP_XOR_QUAD_CurrentVersionRun_b8ab {
  strings:
    $key_b8ab = { eb c4 [2] cf ca [2] e4 e6 [2] ca c4 [2] de df [2] d1 c5 [2] cf d8 [2] cd d9 [2] d6 df [2] ca d8 [2] d6 f7 }

  condition:
    any of them
}