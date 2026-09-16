rule TTP_XOR_WriteProcessMemory_2428 {
  strings:
    $key_2428 = { 73 5a [2] 41 78 [2] 47 4d [2] 69 4d [2] 56 51 }

  condition:
    any of them
}