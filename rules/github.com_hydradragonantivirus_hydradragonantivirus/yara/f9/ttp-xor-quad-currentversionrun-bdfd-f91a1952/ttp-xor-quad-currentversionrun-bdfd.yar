rule TTP_XOR_QUAD_CurrentVersionRun_bdfd {
  strings:
    $key_bdfd = { ee 92 [2] ca 9c [2] e1 b0 [2] cf 92 [2] db 89 [2] d4 93 [2] ca 8e [2] c8 8f [2] d3 89 [2] cf 8e [2] d3 a1 }

  condition:
    any of them
}