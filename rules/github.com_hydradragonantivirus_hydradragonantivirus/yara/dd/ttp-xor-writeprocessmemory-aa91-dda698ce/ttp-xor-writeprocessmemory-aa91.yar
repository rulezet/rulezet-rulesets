rule TTP_XOR_WriteProcessMemory_aa91 {
  strings:
    $key_aa91 = { fd e3 [2] cf c1 [2] c9 f4 [2] e7 f4 [2] d8 e8 }

  condition:
    any of them
}