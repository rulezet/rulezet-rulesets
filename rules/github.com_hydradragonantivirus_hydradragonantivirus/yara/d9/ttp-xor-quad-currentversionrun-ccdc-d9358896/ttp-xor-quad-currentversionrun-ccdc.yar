rule TTP_XOR_QUAD_CurrentVersionRun_ccdc {
  strings:
    $key_ccdc = { 9f b3 [2] bb bd [2] 90 91 [2] be b3 [2] aa a8 [2] a5 b2 [2] bb af [2] b9 ae [2] a2 a8 [2] be af [2] a2 80 }

  condition:
    any of them
}