rule TTP_XOR_QUAD_CurrentVersionRun_bd0f {
  strings:
    $key_bd0f = { ee 60 [2] ca 6e [2] e1 42 [2] cf 60 [2] db 7b [2] d4 61 [2] ca 7c [2] c8 7d [2] d3 7b [2] cf 7c [2] d3 53 }

  condition:
    any of them
}