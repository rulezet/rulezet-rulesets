rule TTP_XOR_QUAD_CurrentVersionRun_933c {
  strings:
    $key_933c = { c0 53 [2] e4 5d [2] cf 71 [2] e1 53 [2] f5 48 [2] fa 52 [2] e4 4f [2] e6 4e [2] fd 48 [2] e1 4f [2] fd 60 }

  condition:
    any of them
}