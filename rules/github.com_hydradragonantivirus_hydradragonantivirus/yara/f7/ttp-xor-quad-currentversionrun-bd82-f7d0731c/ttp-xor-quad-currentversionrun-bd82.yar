rule TTP_XOR_QUAD_CurrentVersionRun_bd82 {
  strings:
    $key_bd82 = { ee ed [2] ca e3 [2] e1 cf [2] cf ed [2] db f6 [2] d4 ec [2] ca f1 [2] c8 f0 [2] d3 f6 [2] cf f1 [2] d3 de }

  condition:
    any of them
}