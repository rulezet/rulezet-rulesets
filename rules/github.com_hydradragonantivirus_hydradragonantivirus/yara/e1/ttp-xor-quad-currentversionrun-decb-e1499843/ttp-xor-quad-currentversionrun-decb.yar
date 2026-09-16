rule TTP_XOR_QUAD_CurrentVersionRun_decb {
  strings:
    $key_decb = { 8d a4 [2] a9 aa [2] 82 86 [2] ac a4 [2] b8 bf [2] b7 a5 [2] a9 b8 [2] ab b9 [2] b0 bf [2] ac b8 [2] b0 97 }

  condition:
    any of them
}