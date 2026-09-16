rule TTP_XOR_QUAD_CurrentVersionRun_bd2f {
  strings:
    $key_bd2f = { ee 40 [2] ca 4e [2] e1 62 [2] cf 40 [2] db 5b [2] d4 41 [2] ca 5c [2] c8 5d [2] d3 5b [2] cf 5c [2] d3 73 }

  condition:
    any of them
}