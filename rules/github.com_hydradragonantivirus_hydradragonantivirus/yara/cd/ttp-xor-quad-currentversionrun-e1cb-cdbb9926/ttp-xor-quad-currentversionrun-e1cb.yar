rule TTP_XOR_QUAD_CurrentVersionRun_e1cb {
  strings:
    $key_e1cb = { b2 a4 [2] 96 aa [2] bd 86 [2] 93 a4 [2] 87 bf [2] 88 a5 [2] 96 b8 [2] 94 b9 [2] 8f bf [2] 93 b8 [2] 8f 97 }

  condition:
    any of them
}