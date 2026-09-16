rule TTP_XOR_WriteProcessMemory_213d {
  strings:
    $key_213d = { 76 4f [2] 44 6d [2] 42 58 [2] 6c 58 [2] 53 44 }

  condition:
    any of them
}