rule TTP_XOR_QUAD_CurrentVersionRun_fcde {
  strings:
    $key_fcde = { af b1 [2] 8b bf [2] a0 93 [2] 8e b1 [2] 9a aa [2] 95 b0 [2] 8b ad [2] 89 ac [2] 92 aa [2] 8e ad [2] 92 82 }

  condition:
    any of them
}