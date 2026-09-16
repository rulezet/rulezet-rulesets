rule TTP_XOR_WriteProcessMemory_91d7 {
  strings:
    $key_91d7 = { c6 a5 [2] f4 87 [2] f2 b2 [2] dc b2 [2] e3 ae }

  condition:
    any of them
}