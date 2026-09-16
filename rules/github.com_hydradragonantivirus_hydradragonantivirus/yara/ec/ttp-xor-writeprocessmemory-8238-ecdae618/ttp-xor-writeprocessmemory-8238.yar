rule TTP_XOR_WriteProcessMemory_8238 {
  strings:
    $key_8238 = { d5 4a [2] e7 68 [2] e1 5d [2] cf 5d [2] f0 41 }

  condition:
    any of them
}