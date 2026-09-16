rule TTP_XOR_QUAD_CurrentVersionRun_b2dc {
  strings:
    $key_b2dc = { e1 b3 [2] c5 bd [2] ee 91 [2] c0 b3 [2] d4 a8 [2] db b2 [2] c5 af [2] c7 ae [2] dc a8 [2] c0 af [2] dc 80 }

  condition:
    any of them
}