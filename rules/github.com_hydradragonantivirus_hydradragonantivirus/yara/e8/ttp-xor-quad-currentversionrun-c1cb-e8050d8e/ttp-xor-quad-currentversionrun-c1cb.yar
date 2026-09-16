rule TTP_XOR_QUAD_CurrentVersionRun_c1cb {
  strings:
    $key_c1cb = { 92 a4 [2] b6 aa [2] 9d 86 [2] b3 a4 [2] a7 bf [2] a8 a5 [2] b6 b8 [2] b4 b9 [2] af bf [2] b3 b8 [2] af 97 }

  condition:
    any of them
}