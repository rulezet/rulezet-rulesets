rule TTP_XOR_QUAD_CurrentVersionRun_a91e {
  strings:
    $key_a91e = { fa 71 [2] de 7f [2] f5 53 [2] db 71 [2] cf 6a [2] c0 70 [2] de 6d [2] dc 6c [2] c7 6a [2] db 6d [2] c7 42 }

  condition:
    any of them
}