rule TTP_XOR_QUAD_CurrentVersionRun_dadc {
  strings:
    $key_dadc = { 89 b3 [2] ad bd [2] 86 91 [2] a8 b3 [2] bc a8 [2] b3 b2 [2] ad af [2] af ae [2] b4 a8 [2] a8 af [2] b4 80 }

  condition:
    any of them
}