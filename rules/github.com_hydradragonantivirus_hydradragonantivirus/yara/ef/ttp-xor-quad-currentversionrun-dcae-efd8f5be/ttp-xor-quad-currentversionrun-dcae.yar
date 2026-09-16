rule TTP_XOR_QUAD_CurrentVersionRun_dcae {
  strings:
    $key_dcae = { 8f c1 [2] ab cf [2] 80 e3 [2] ae c1 [2] ba da [2] b5 c0 [2] ab dd [2] a9 dc [2] b2 da [2] ae dd [2] b2 f2 }

  condition:
    any of them
}