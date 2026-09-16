rule TTP_XOR_QUAD_CurrentVersionRun_b9dc {
  strings:
    $key_b9dc = { ea b3 [2] ce bd [2] e5 91 [2] cb b3 [2] df a8 [2] d0 b2 [2] ce af [2] cc ae [2] d7 a8 [2] cb af [2] d7 80 }

  condition:
    any of them
}