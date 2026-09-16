rule TTP_XOR_WriteProcessMemory_f8cc {
  strings:
    $key_f8cc = { af be [2] 9d 9c [2] 9b a9 [2] b5 a9 [2] 8a b5 }

  condition:
    any of them
}