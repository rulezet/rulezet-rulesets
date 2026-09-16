rule TTP_XOR_QUAD_CurrentVersionRun_9adb {
  strings:
    $key_9adb = { c9 b4 [2] ed ba [2] c6 96 [2] e8 b4 [2] fc af [2] f3 b5 [2] ed a8 [2] ef a9 [2] f4 af [2] e8 a8 [2] f4 87 }

  condition:
    any of them
}