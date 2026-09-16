rule TTP_XOR_QUAD_CurrentVersionRun_9480 {
  strings:
    $key_9480 = { c7 ef [2] e3 e1 [2] c8 cd [2] e6 ef [2] f2 f4 [2] fd ee [2] e3 f3 [2] e1 f2 [2] fa f4 [2] e6 f3 [2] fa dc }

  condition:
    any of them
}