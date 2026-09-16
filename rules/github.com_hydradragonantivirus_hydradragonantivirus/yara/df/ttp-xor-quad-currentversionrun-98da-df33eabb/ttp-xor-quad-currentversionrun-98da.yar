rule TTP_XOR_QUAD_CurrentVersionRun_98da {
  strings:
    $key_98da = { cb b5 [2] ef bb [2] c4 97 [2] ea b5 [2] fe ae [2] f1 b4 [2] ef a9 [2] ed a8 [2] f6 ae [2] ea a9 [2] f6 86 }

  condition:
    any of them
}