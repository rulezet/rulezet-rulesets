rule TTP_XOR_WriteProcessMemory_38cc {
  strings:
    $key_38cc = { 6f be [2] 5d 9c [2] 5b a9 [2] 75 a9 [2] 4a b5 }

  condition:
    any of them
}