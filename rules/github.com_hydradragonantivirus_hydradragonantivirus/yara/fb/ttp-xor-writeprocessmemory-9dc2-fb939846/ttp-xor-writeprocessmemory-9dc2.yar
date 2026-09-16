rule TTP_XOR_WriteProcessMemory_9dc2 {
  strings:
    $key_9dc2 = { ca b0 [2] f8 92 [2] fe a7 [2] d0 a7 [2] ef bb }

  condition:
    any of them
}