rule TTP_XOR_WriteProcessMemory_7ad3 {
  strings:
    $key_7ad3 = { 2d a1 [2] 1f 83 [2] 19 b6 [2] 37 b6 [2] 08 aa }

  condition:
    any of them
}