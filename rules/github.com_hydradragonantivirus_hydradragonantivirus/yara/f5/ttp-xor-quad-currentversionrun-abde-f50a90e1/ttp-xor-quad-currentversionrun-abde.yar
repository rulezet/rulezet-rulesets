rule TTP_XOR_QUAD_CurrentVersionRun_abde {
  strings:
    $key_abde = { f8 b1 [2] dc bf [2] f7 93 [2] d9 b1 [2] cd aa [2] c2 b0 [2] dc ad [2] de ac [2] c5 aa [2] d9 ad [2] c5 82 }

  condition:
    any of them
}