rule TTP_XOR_QUAD_CurrentVersionRun_1bae {
  strings:
    $key_1bae = { 48 c1 [2] 6c cf [2] 47 e3 [2] 69 c1 [2] 7d da [2] 72 c0 [2] 6c dd [2] 6e dc [2] 75 da [2] 69 dd [2] 75 f2 }

  condition:
    any of them
}