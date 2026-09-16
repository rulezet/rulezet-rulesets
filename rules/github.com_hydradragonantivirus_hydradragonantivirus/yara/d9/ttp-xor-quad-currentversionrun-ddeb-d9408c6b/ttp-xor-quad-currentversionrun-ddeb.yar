rule TTP_XOR_QUAD_CurrentVersionRun_ddeb {
  strings:
    $key_ddeb = { 8e 84 [2] aa 8a [2] 81 a6 [2] af 84 [2] bb 9f [2] b4 85 [2] aa 98 [2] a8 99 [2] b3 9f [2] af 98 [2] b3 b7 }

  condition:
    any of them
}