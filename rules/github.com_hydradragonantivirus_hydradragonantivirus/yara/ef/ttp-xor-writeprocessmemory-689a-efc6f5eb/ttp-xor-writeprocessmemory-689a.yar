rule TTP_XOR_WriteProcessMemory_689a {
  strings:
    $key_689a = { 3f e8 [2] 0d ca [2] 0b ff [2] 25 ff [2] 1a e3 }

  condition:
    any of them
}