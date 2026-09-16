rule TTP_XOR_WriteProcessMemory_791d {
  strings:
    $key_791d = { 2e 6f [2] 1c 4d [2] 1a 78 [2] 34 78 [2] 0b 64 }

  condition:
    any of them
}