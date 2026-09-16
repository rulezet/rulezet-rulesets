rule TTP_XOR_QUAD_CurrentVersionRun_95dc {
  strings:
    $key_95dc = { c6 b3 [2] e2 bd [2] c9 91 [2] e7 b3 [2] f3 a8 [2] fc b2 [2] e2 af [2] e0 ae [2] fb a8 [2] e7 af [2] fb 80 }

  condition:
    any of them
}