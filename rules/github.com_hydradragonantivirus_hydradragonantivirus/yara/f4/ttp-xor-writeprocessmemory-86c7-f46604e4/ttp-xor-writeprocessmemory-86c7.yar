rule TTP_XOR_WriteProcessMemory_86c7 {
  strings:
    $key_86c7 = { d1 b5 [2] e3 97 [2] e5 a2 [2] cb a2 [2] f4 be }

  condition:
    any of them
}