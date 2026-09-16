rule TTP_XOR_QUAD_CurrentVersionRun_8a10 {
  strings:
    $key_8a10 = { d9 7f [2] fd 71 [2] d6 5d [2] f8 7f [2] ec 64 [2] e3 7e [2] fd 63 [2] ff 62 [2] e4 64 [2] f8 63 [2] e4 4c }

  condition:
    any of them
}