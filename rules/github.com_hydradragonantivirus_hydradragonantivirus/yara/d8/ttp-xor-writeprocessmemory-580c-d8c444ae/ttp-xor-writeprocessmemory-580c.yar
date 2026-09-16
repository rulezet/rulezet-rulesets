rule TTP_XOR_WriteProcessMemory_580c {
  strings:
    $key_580c = { 0f 7e [2] 3d 5c [2] 3b 69 [2] 15 69 [2] 2a 75 }

  condition:
    any of them
}