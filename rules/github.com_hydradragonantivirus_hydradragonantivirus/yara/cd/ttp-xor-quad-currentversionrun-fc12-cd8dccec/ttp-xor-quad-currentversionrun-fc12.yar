rule TTP_XOR_QUAD_CurrentVersionRun_fc12 {
  strings:
    $key_fc12 = { af 7d [2] 8b 73 [2] a0 5f [2] 8e 7d [2] 9a 66 [2] 95 7c [2] 8b 61 [2] 89 60 [2] 92 66 [2] 8e 61 [2] 92 4e }

  condition:
    any of them
}