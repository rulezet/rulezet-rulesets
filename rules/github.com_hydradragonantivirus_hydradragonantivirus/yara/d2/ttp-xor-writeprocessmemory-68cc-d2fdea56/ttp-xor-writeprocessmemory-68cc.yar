rule TTP_XOR_WriteProcessMemory_68cc {
  strings:
    $key_68cc = { 3f be [2] 0d 9c [2] 0b a9 [2] 25 a9 [2] 1a b5 }

  condition:
    any of them
}