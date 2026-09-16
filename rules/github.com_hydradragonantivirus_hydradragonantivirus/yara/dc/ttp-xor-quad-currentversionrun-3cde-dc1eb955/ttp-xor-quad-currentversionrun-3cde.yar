rule TTP_XOR_QUAD_CurrentVersionRun_3cde {
  strings:
    $key_3cde = { 6f b1 [2] 4b bf [2] 60 93 [2] 4e b1 [2] 5a aa [2] 55 b0 [2] 4b ad [2] 49 ac [2] 52 aa [2] 4e ad [2] 52 82 }

  condition:
    any of them
}