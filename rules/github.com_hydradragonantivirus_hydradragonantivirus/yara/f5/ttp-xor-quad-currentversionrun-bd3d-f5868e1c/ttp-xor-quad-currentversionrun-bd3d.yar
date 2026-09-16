rule TTP_XOR_QUAD_CurrentVersionRun_bd3d {
  strings:
    $key_bd3d = { ee 52 [2] ca 5c [2] e1 70 [2] cf 52 [2] db 49 [2] d4 53 [2] ca 4e [2] c8 4f [2] d3 49 [2] cf 4e [2] d3 61 }

  condition:
    any of them
}