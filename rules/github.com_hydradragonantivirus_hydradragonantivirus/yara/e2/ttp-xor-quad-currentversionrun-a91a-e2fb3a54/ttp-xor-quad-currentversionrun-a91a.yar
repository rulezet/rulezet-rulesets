rule TTP_XOR_QUAD_CurrentVersionRun_a91a {
  strings:
    $key_a91a = { fa 75 [2] de 7b [2] f5 57 [2] db 75 [2] cf 6e [2] c0 74 [2] de 69 [2] dc 68 [2] c7 6e [2] db 69 [2] c7 46 }

  condition:
    any of them
}