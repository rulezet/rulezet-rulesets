rule TTP_XOR_QUAD_CurrentVersionRun_d814 {
  strings:
    $key_d814 = { 8b 7b [2] af 75 [2] 84 59 [2] aa 7b [2] be 60 [2] b1 7a [2] af 67 [2] ad 66 [2] b6 60 [2] aa 67 [2] b6 48 }

  condition:
    any of them
}