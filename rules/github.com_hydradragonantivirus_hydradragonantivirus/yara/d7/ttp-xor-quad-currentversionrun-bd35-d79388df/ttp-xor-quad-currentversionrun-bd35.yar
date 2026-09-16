rule TTP_XOR_QUAD_CurrentVersionRun_bd35 {
  strings:
    $key_bd35 = { ee 5a [2] ca 54 [2] e1 78 [2] cf 5a [2] db 41 [2] d4 5b [2] ca 46 [2] c8 47 [2] d3 41 [2] cf 46 [2] d3 69 }

  condition:
    any of them
}