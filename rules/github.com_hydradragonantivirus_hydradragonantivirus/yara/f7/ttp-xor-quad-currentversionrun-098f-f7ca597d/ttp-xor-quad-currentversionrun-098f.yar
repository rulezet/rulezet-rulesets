rule TTP_XOR_QUAD_CurrentVersionRun_098f {
  strings:
    $key_098f = { 5a e0 [2] 7e ee [2] 55 c2 [2] 7b e0 [2] 6f fb [2] 60 e1 [2] 7e fc [2] 7c fd [2] 67 fb [2] 7b fc [2] 67 d3 }

  condition:
    any of them
}