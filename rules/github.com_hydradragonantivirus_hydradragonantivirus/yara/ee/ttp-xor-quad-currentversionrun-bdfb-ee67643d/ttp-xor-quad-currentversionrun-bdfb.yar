rule TTP_XOR_QUAD_CurrentVersionRun_bdfb {
  strings:
    $key_bdfb = { ee 94 [2] ca 9a [2] e1 b6 [2] cf 94 [2] db 8f [2] d4 95 [2] ca 88 [2] c8 89 [2] d3 8f [2] cf 88 [2] d3 a7 }

  condition:
    any of them
}