rule TTP_XOR_QUAD_CurrentVersionRun_f9de {
  strings:
    $key_f9de = { aa b1 [2] 8e bf [2] a5 93 [2] 8b b1 [2] 9f aa [2] 90 b0 [2] 8e ad [2] 8c ac [2] 97 aa [2] 8b ad [2] 97 82 }

  condition:
    any of them
}