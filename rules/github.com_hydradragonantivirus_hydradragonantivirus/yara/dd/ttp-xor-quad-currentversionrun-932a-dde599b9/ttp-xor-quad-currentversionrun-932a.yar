rule TTP_XOR_QUAD_CurrentVersionRun_932a {
  strings:
    $key_932a = { c0 45 [2] e4 4b [2] cf 67 [2] e1 45 [2] f5 5e [2] fa 44 [2] e4 59 [2] e6 58 [2] fd 5e [2] e1 59 [2] fd 76 }

  condition:
    any of them
}