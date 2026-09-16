rule TTP_XOR_QUAD_CurrentVersionRun_dd0f {
  strings:
    $key_dd0f = { 8e 60 [2] aa 6e [2] 81 42 [2] af 60 [2] bb 7b [2] b4 61 [2] aa 7c [2] a8 7d [2] b3 7b [2] af 7c [2] b3 53 }

  condition:
    any of them
}