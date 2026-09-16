rule TTP_XOR_QUAD_CurrentVersionRun_98d1 {
  strings:
    $key_98d1 = { cb be [2] ef b0 [2] c4 9c [2] ea be [2] fe a5 [2] f1 bf [2] ef a2 [2] ed a3 [2] f6 a5 [2] ea a2 [2] f6 8d }

  condition:
    any of them
}