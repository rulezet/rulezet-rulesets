rule TTP_XOR_QUAD_CurrentVersionRun_9ff2 {
  strings:
    $key_9ff2 = { cc 9d [2] e8 93 [2] c3 bf [2] ed 9d [2] f9 86 [2] f6 9c [2] e8 81 [2] ea 80 [2] f1 86 [2] ed 81 [2] f1 ae }

  condition:
    any of them
}