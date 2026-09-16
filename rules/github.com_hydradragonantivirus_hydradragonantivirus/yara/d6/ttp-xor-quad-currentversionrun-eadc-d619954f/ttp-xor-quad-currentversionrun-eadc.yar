rule TTP_XOR_QUAD_CurrentVersionRun_eadc {
  strings:
    $key_eadc = { b9 b3 [2] 9d bd [2] b6 91 [2] 98 b3 [2] 8c a8 [2] 83 b2 [2] 9d af [2] 9f ae [2] 84 a8 [2] 98 af [2] 84 80 }

  condition:
    any of them
}