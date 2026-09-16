rule TTP_XOR_QUAD_CurrentVersionRun_d9ae {
  strings:
    $key_d9ae = { 8a c1 [2] ae cf [2] 85 e3 [2] ab c1 [2] bf da [2] b0 c0 [2] ae dd [2] ac dc [2] b7 da [2] ab dd [2] b7 f2 }

  condition:
    any of them
}