rule TTP_XOR_QUAD_CurrentVersionRun_d7cb {
  strings:
    $key_d7cb = { 84 a4 [2] a0 aa [2] 8b 86 [2] a5 a4 [2] b1 bf [2] be a5 [2] a0 b8 [2] a2 b9 [2] b9 bf [2] a5 b8 [2] b9 97 }

  condition:
    any of them
}