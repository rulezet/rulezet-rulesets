rule TTP_XOR_QUAD_CurrentVersionRun_863c {
  strings:
    $key_863c = { d5 53 [2] f1 5d [2] da 71 [2] f4 53 [2] e0 48 [2] ef 52 [2] f1 4f [2] f3 4e [2] e8 48 [2] f4 4f [2] e8 60 }

  condition:
    any of them
}