rule TTP_XOR_WriteProcessMemory_e138 {
  strings:
    $key_e138 = { b6 4a [2] 84 68 [2] 82 5d [2] ac 5d [2] 93 41 }

  condition:
    any of them
}