rule TTP_XOR_QUAD_CurrentVersionRun_aede {
  strings:
    $key_aede = { fd b1 [2] d9 bf [2] f2 93 [2] dc b1 [2] c8 aa [2] c7 b0 [2] d9 ad [2] db ac [2] c0 aa [2] dc ad [2] c0 82 }

  condition:
    any of them
}