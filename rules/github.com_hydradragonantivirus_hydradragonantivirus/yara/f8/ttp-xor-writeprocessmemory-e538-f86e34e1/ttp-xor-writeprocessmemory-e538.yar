rule TTP_XOR_WriteProcessMemory_e538 {
  strings:
    $key_e538 = { b2 4a [2] 80 68 [2] 86 5d [2] a8 5d [2] 97 41 }

  condition:
    any of them
}