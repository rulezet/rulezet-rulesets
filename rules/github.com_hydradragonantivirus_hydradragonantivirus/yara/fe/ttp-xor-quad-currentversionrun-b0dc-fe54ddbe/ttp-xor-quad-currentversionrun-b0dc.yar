rule TTP_XOR_QUAD_CurrentVersionRun_b0dc {
  strings:
    $key_b0dc = { e3 b3 [2] c7 bd [2] ec 91 [2] c2 b3 [2] d6 a8 [2] d9 b2 [2] c7 af [2] c5 ae [2] de a8 [2] c2 af [2] de 80 }

  condition:
    any of them
}