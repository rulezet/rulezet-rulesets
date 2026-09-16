rule TTP_XOR_WriteProcessMemory_f911 {
  strings:
    $key_f911 = { ae 63 [2] 9c 41 [2] 9a 74 [2] b4 74 [2] 8b 68 }

  condition:
    any of them
}