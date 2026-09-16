rule TTP_XOR_WriteProcessMemory_3ee8 {
  strings:
    $key_3ee8 = { 69 9a [2] 5b b8 [2] 5d 8d [2] 73 8d [2] 4c 91 }

  condition:
    any of them
}