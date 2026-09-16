rule TTP_XOR_QUAD_CurrentVersionRun_edce {
  strings:
    $key_edce = { be a1 [2] 9a af [2] b1 83 [2] 9f a1 [2] 8b ba [2] 84 a0 [2] 9a bd [2] 98 bc [2] 83 ba [2] 9f bd [2] 83 92 }

  condition:
    any of them
}