rule TTP_XOR_QUAD_CurrentVersionRun_9f32 {
  strings:
    $key_9f32 = { cc 5d [2] e8 53 [2] c3 7f [2] ed 5d [2] f9 46 [2] f6 5c [2] e8 41 [2] ea 40 [2] f1 46 [2] ed 41 [2] f1 6e }

  condition:
    any of them
}