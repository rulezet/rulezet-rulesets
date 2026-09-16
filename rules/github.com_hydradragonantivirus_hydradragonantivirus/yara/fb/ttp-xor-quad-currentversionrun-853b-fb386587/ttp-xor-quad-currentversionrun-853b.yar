rule TTP_XOR_QUAD_CurrentVersionRun_853b {
  strings:
    $key_853b = { d6 54 [2] f2 5a [2] d9 76 [2] f7 54 [2] e3 4f [2] ec 55 [2] f2 48 [2] f0 49 [2] eb 4f [2] f7 48 [2] eb 67 }

  condition:
    any of them
}