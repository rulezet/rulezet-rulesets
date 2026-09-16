rule TTP_XOR_QUAD_CurrentVersionRun_ddf2 {
  strings:
    $key_ddf2 = { 8e 9d [2] aa 93 [2] 81 bf [2] af 9d [2] bb 86 [2] b4 9c [2] aa 81 [2] a8 80 [2] b3 86 [2] af 81 [2] b3 ae }

  condition:
    any of them
}